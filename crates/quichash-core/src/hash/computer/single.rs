use std::fs::File;
use std::io::IsTerminal;
use std::io::{Read, Seek};
use std::path::Path;
use std::str::FromStr;

#[cfg(feature = "mmap")]
use memmap2::Mmap;

use super::super::HashResult;
use super::super::algorithm::Algorithm;
use super::super::file::*;
use super::super::hasher::{Hasher, bytes_to_hex};
use super::super::registry::HashRegistry;
use super::HashComputer;
use crate::error::HashUtilityError;

impl HashComputer {
    /// Hash one file from an outer file-parallel pipeline. The caller owns a
    /// reusable buffer, and this method deliberately avoids nested Rayon work.
    #[cfg(feature = "filesystem")]
    #[allow(unsafe_code)]
    pub(crate) fn compute_hash_for_worker(
        &self,
        path: &Path,
        algorithm: &str,
        fast_mode: bool,
        file_size: u64,
        buffer: &mut [u8],
    ) -> Result<HashResult, HashUtilityError> {
        let parsed = Algorithm::from_str(algorithm)?;
        let mode = if fast_mode {
            super::super::HashMode::Sampled
        } else {
            super::super::HashMode::Full
        };
        let digest =
            super::super::file::hash_file_mode_worker(path, &[parsed], mode, file_size, buffer)?
                .remove(0);
        Ok(HashResult {
            algorithm: algorithm.to_owned(),
            hash: digest.to_hex(),
            file_path: path.to_owned(),
        })
    }

    /// Compute hash for a single file using streaming I/O or memory mapping
    ///
    /// Uses buffered I/O for small files and memory mapping for larger files on
    /// 64-bit targets. 32-bit targets cap mappings at 2 GiB.
    ///
    /// # Safety
    ///
    /// Memory mapping assumes the file will not be modified by other processes during hashing.
    /// If the file is modified concurrently, the hash result may be inconsistent.
    /// This is acceptable for typical use cases where files are not being actively modified.
    #[allow(unsafe_code)]
    pub fn compute_hash(
        &self,
        path: &Path,
        algorithm: &str,
    ) -> Result<HashResult, HashUtilityError> {
        self.compute_hash_with_progress(path, algorithm, false)
    }

    /// Compute hash for a single file with optional progress bar
    ///
    /// If show_progress is true and the file is larger than 1GB and stdout is a TTY,
    /// displays a progress bar that updates 10 times per second.
    #[allow(unsafe_code)]
    pub fn compute_hash_with_progress(
        &self,
        path: &Path,
        algorithm: &str,
        show_progress: bool,
    ) -> Result<HashResult, HashUtilityError> {
        if !show_progress && Algorithm::from_str(algorithm).ok() == Some(Algorithm::Blake3) {
            let digest = hash_file(path, &[Algorithm::Blake3])?.remove(0);
            return Ok(HashResult {
                algorithm: algorithm.to_owned(),
                hash: digest.to_hex(),
                file_path: path.to_owned(),
            });
        }
        // Get hasher for the specified algorithm
        let mut hasher = HashRegistry::get_hasher(algorithm)?;

        // Open file for reading with better error context
        let file = super::super::io_strategy::open(path, super::super::HashMode::Full)
            .map_err(|e| HashUtilityError::from_io_error(e, "reading", Some(path.to_path_buf())))?;

        // Get file size to determine whether to use memory mapping
        let file_size = file
            .metadata()
            .map_err(|e| {
                HashUtilityError::from_io_error(e, "reading metadata", Some(path.to_path_buf()))
            })?
            .len();

        // Determine if we should show progress bar
        let should_show_progress =
            show_progress && file_size > PROGRESS_BAR_THRESHOLD && std::io::stdout().is_terminal();

        // Use memory mapping only when it amortizes mapping/page-fault overhead.
        #[cfg(feature = "mmap")]
        {
            if (MMAP_MIN_SIZE..MMAP_THRESHOLD).contains(&file_size) {
                // Try to memory map the file
                match unsafe { Mmap::map(&file) } {
                    Ok(mmap) => {
                        // Hash the entire mapped file in one go
                        // Note: Progress bar not shown for mmap as it's very fast
                        hasher.update(&mmap[..]);
                    }
                    Err(_) => {
                        // Fall back to buffered reading if mmap fails
                        if should_show_progress {
                            self.hash_with_buffered_io_progress(
                                &mut hasher,
                                file,
                                path,
                                file_size,
                            )?;
                        } else {
                            self.hash_with_buffered_io(&mut hasher, file, path)?;
                        }
                    }
                }
            } else {
                // Use buffered reading outside the platform's mapping range.
                if should_show_progress {
                    self.hash_with_buffered_io_progress(&mut hasher, file, path, file_size)?;
                } else {
                    self.hash_with_buffered_io(&mut hasher, file, path)?;
                }
            }
        }
        #[cfg(not(feature = "mmap"))]
        {
            if should_show_progress {
                self.hash_with_buffered_io_progress(&mut hasher, file, path, file_size)?;
            } else {
                self.hash_with_buffered_io(&mut hasher, file, path)?;
            }
        }

        // Finalize hash and convert to hex
        let hash_bytes = hasher.finalize();
        let hash_hex = bytes_to_hex(&hash_bytes);

        Ok(HashResult {
            algorithm: algorithm.to_string(),
            hash: hash_hex,
            file_path: path.to_path_buf(),
        })
    }

    /// Helper method to hash a file using buffered I/O
    pub(crate) fn hash_with_buffered_io(
        &self,
        hasher: &mut Box<dyn Hasher>,
        mut file: File,
        path: &Path,
    ) -> Result<(), HashUtilityError> {
        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            let bytes_read = file.read(&mut buffer).map_err(|e| {
                HashUtilityError::from_io_error(e, "reading", Some(path.to_path_buf()))
            })?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(())
    }

    /// Helper method to hash a file using buffered I/O with progress bar
    pub(crate) fn hash_with_buffered_io_progress(
        &self,
        hasher: &mut Box<dyn Hasher>,
        mut file: File,
        path: &Path,
        file_size: u64,
    ) -> Result<(), HashUtilityError> {
        use crate::operation::{
            LegacyProgress as ProgressBar, LegacyProgressStyle as ProgressStyle,
        };
        use std::time::{Duration, Instant};

        // Create progress bar
        let pb = ProgressBar::new(file_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{msg}\n[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
                )
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_message(format!("Hashing: {}", path.display()));

        let mut buffer = vec![0u8; self.buffer_size];
        let mut bytes_processed = 0u64;
        let mut last_update = Instant::now();
        let update_interval = Duration::from_millis(PROGRESS_UPDATE_INTERVAL_MS);

        loop {
            let bytes_read = file.read(&mut buffer).map_err(|e| {
                pb.finish_and_clear();
                HashUtilityError::from_io_error(e, "reading", Some(path.to_path_buf()))
            })?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
            bytes_processed += bytes_read as u64;

            // Update progress bar at the specified interval
            let now = Instant::now();
            if now.duration_since(last_update) >= update_interval {
                pb.set_position(bytes_processed);
                last_update = now;
            }
        }

        // Finish progress bar
        pb.finish_and_clear();

        Ok(())
    }

    /// Compute hash for a file using fast mode (sampling strategy)
    ///
    /// For files larger than 300MB, samples three 100MB regions:
    /// - First 100MB
    /// - Middle 100MB (centered at file_size/2)
    /// - Last 100MB
    ///
    /// For files smaller than 300MB, uses the full file.
    pub fn compute_hash_fast(
        &self,
        path: &Path,
        algorithm: &str,
    ) -> Result<HashResult, HashUtilityError> {
        // Get hasher for the specified algorithm
        let mut hasher = HashRegistry::get_hasher(algorithm)?;

        // Open file for reading with better error context
        let mut file = super::super::io_strategy::open(path, super::super::HashMode::Sampled)
            .map_err(|e| HashUtilityError::from_io_error(e, "reading", Some(path.to_path_buf())))?;

        // Get file size
        let file_size = file
            .metadata()
            .map_err(|e| {
                HashUtilityError::from_io_error(e, "reading metadata", Some(path.to_path_buf()))
            })?
            .len();

        // If file is smaller than threshold, hash the entire file
        if file_size < FAST_MODE_THRESHOLD {
            let mut buffer = vec![0u8; self.buffer_size];
            loop {
                let bytes_read = file.read(&mut buffer).map_err(|e| {
                    HashUtilityError::from_io_error(e, "reading", Some(path.to_path_buf()))
                })?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
        } else {
            // Sample three regions: first 100MB, middle 100MB, last 100MB

            // Read first 100MB
            let mut buffer = vec![0_u8; self.buffer_size];
            self.read_region(
                &mut file,
                &mut hasher,
                &mut buffer,
                0,
                FAST_MODE_SAMPLE_SIZE,
                path,
            )?;

            // Calculate middle region: centered at file_size/2
            let middle_start = (file_size / 2).saturating_sub(FAST_MODE_SAMPLE_SIZE / 2);
            self.read_region(
                &mut file,
                &mut hasher,
                &mut buffer,
                middle_start,
                FAST_MODE_SAMPLE_SIZE,
                path,
            )?;

            // Read last 100MB
            let last_start = file_size.saturating_sub(FAST_MODE_SAMPLE_SIZE);
            self.read_region(
                &mut file,
                &mut hasher,
                &mut buffer,
                last_start,
                FAST_MODE_SAMPLE_SIZE,
                path,
            )?;
        }

        // Finalize hash and convert to hex
        let hash_bytes = hasher.finalize();
        let hash_hex = bytes_to_hex(&hash_bytes);

        Ok(HashResult {
            algorithm: algorithm.to_string(),
            hash: hash_hex,
            file_path: path.to_path_buf(),
        })
    }

    /// Helper function to read a specific region of a file
    fn read_region(
        &self,
        file: &mut File,
        hasher: &mut Box<dyn Hasher>,
        buffer: &mut [u8],
        start: u64,
        length: u64,
        path: &Path,
    ) -> Result<(), HashUtilityError> {
        // Seek to the start position
        file.seek(std::io::SeekFrom::Start(start))
            .map_err(|e| HashUtilityError::from_io_error(e, "seeking", Some(path.to_path_buf())))?;

        // Read up to 'length' bytes
        let mut bytes_remaining = length;

        while bytes_remaining > 0 {
            let to_read = std::cmp::min(bytes_remaining, buffer.len() as u64) as usize;
            let bytes_read = file.read(&mut buffer[..to_read]).map_err(|e| {
                HashUtilityError::from_io_error(e, "reading", Some(path.to_path_buf()))
            })?;

            if bytes_read == 0 {
                break; // End of file
            }

            hasher.update(&buffer[..bytes_read]);
            bytes_remaining -= bytes_read as u64;
        }

        Ok(())
    }
}
