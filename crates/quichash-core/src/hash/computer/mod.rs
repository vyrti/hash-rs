use std::fs::File;
use std::io::IsTerminal;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(feature = "mmap")]
use memmap2::Mmap;

use super::file::*;
use super::hasher::{bytes_to_hex, Hasher};
use super::registry::HashRegistry;
use super::HashResult;
use crate::error::HashUtilityError;

mod single;

/// Hash computer with streaming I/O
pub struct HashComputer {
    pub(crate) buffer_size: usize,
}

impl HashComputer {
    /// Create a new HashComputer with default buffer size (1MB)
    pub fn new() -> Self {
        Self {
            buffer_size: 1024 * 1024,
        }
    }

    /// Create a new HashComputer with custom buffer size
    pub fn with_buffer_size(buffer_size: usize) -> Self {
        Self { buffer_size }
    }

    /// Return the buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Compute hash from text string
    pub fn compute_hash_text(
        &self,
        text: &str,
        algorithm: &str,
    ) -> Result<HashResult, HashUtilityError> {
        // Get hasher for the specified algorithm
        let mut hasher = HashRegistry::get_hasher(algorithm)?;

        // Hash the UTF-8 bytes of the text
        hasher.update(text.as_bytes());

        // Finalize hash and convert to hex
        let hash_bytes = hasher.finalize();
        let hash_hex = bytes_to_hex(&hash_bytes);

        Ok(HashResult {
            algorithm: algorithm.to_string(),
            hash: hash_hex,
            file_path: PathBuf::from("<text>"), // Use "<text>" to indicate text input
        })
    }

    /// Compute multiple hashes from text string in a single pass
    pub fn compute_multiple_hashes_text(
        &self,
        text: &str,
        algorithms: &[String],
    ) -> Result<Vec<HashResult>, HashUtilityError> {
        // Get hashers for all specified algorithms
        let mut hashers: Vec<(String, Box<dyn Hasher>)> = Vec::new();
        for algorithm in algorithms {
            let hasher = HashRegistry::get_hasher(algorithm)?;
            hashers.push((algorithm.clone(), hasher));
        }

        // Hash the UTF-8 bytes of the text with all hashers
        let text_bytes = text.as_bytes();
        for (_, hasher) in &mut hashers {
            hasher.update(text_bytes);
        }

        // Finalize all hashes and collect results
        let mut results = Vec::new();
        for (algorithm, hasher) in hashers {
            let hash_bytes = hasher.finalize();
            let hash_hex = bytes_to_hex(&hash_bytes);

            results.push(HashResult {
                algorithm,
                hash: hash_hex,
                file_path: PathBuf::from("<text>"), // Use "<text>" to indicate text input
            });
        }

        Ok(results)
    }

    /// Compute hash from stdin using streaming I/O
    pub fn compute_hash_stdin(&self, algorithm: &str) -> Result<HashResult, HashUtilityError> {
        use std::io::{stdin, Read};

        // Get hasher for the specified algorithm
        let mut hasher = HashRegistry::get_hasher(algorithm)?;

        // Get stdin handle
        let mut stdin = stdin();

        // Create buffer for streaming reads
        let mut buffer = vec![0u8; self.buffer_size];

        // Stream stdin data through hasher
        loop {
            let bytes_read = stdin
                .read(&mut buffer)
                .map_err(|e| HashUtilityError::from_io_error(e, "reading from stdin", None))?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        // Finalize hash and convert to hex
        let hash_bytes = hasher.finalize();
        let hash_hex = bytes_to_hex(&hash_bytes);

        Ok(HashResult {
            algorithm: algorithm.to_string(),
            hash: hash_hex,
            file_path: PathBuf::from("-"), // Use "-" to indicate stdin
        })
    }

    /// Compute multiple hashes from stdin in a single pass
    pub fn compute_multiple_hashes_stdin(
        &self,
        algorithms: &[String],
    ) -> Result<Vec<HashResult>, HashUtilityError> {
        use std::io::{stdin, Read};

        // Get hashers for all specified algorithms
        let mut hashers: Vec<(String, Box<dyn Hasher>)> = Vec::new();
        for algorithm in algorithms {
            let hasher = HashRegistry::get_hasher(algorithm)?;
            hashers.push((algorithm.clone(), hasher));
        }

        // Get stdin handle
        let mut stdin = stdin();

        // Create buffer for streaming reads
        let mut buffer = vec![0u8; self.buffer_size];

        // Stream stdin data through all hashers in single pass
        loop {
            let bytes_read = stdin
                .read(&mut buffer)
                .map_err(|e| HashUtilityError::from_io_error(e, "reading from stdin", None))?;
            if bytes_read == 0 {
                break;
            }

            // Update all hashers with the same data
            for (_, hasher) in &mut hashers {
                hasher.update(&buffer[..bytes_read]);
            }
        }

        // Finalize all hashes and collect results
        let mut results = Vec::new();
        for (algorithm, hasher) in hashers {
            let hash_bytes = hasher.finalize();
            let hash_hex = bytes_to_hex(&hash_bytes);

            results.push(HashResult {
                algorithm,
                hash: hash_hex,
                file_path: PathBuf::from("-"), // Use "-" to indicate stdin
            });
        }

        Ok(results)
    }

    /// Compute multiple hashes for a single file in a single pass
    ///
    /// For files smaller than 2GB, uses memory mapping to avoid kernel-to-userspace copy overhead.
    /// For files larger than 2GB, falls back to buffered reading with 1MB buffer.
    ///
    /// # Safety
    ///
    /// Memory mapping assumes the file will not be modified by other processes during hashing.
    /// If the file is modified concurrently, the hash results may be inconsistent.
    pub fn compute_multiple_hashes(
        &self,
        path: &Path,
        algorithms: &[String],
    ) -> Result<Vec<HashResult>, HashUtilityError> {
        self.compute_multiple_hashes_with_progress(path, algorithms, false)
    }

    /// Compute multiple hashes for a single file with optional progress bar
    ///
    /// If show_progress is true and the file is larger than 1GB and stdout is a TTY,
    /// displays a progress bar that updates 10 times per second.
    #[allow(unsafe_code)]
    pub fn compute_multiple_hashes_with_progress(
        &self,
        path: &Path,
        algorithms: &[String],
        show_progress: bool,
    ) -> Result<Vec<HashResult>, HashUtilityError> {
        // Get hashers for all specified algorithms
        let mut hashers: Vec<(String, Box<dyn Hasher>)> = Vec::new();
        for algorithm in algorithms {
            let hasher = HashRegistry::get_hasher(algorithm)?;
            hashers.push((algorithm.clone(), hasher));
        }

        // Open file for reading with better error context
        let file = File::open(path)
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

        // Use memory mapping for files smaller than 2GB when requested.
        #[cfg(feature = "mmap")]
        {
            if file_size > 0 && file_size < MMAP_THRESHOLD {
                // Try to memory map the file
                match unsafe { Mmap::map(&file) } {
                    Ok(mmap) => {
                        // Hash the entire mapped file with all hashers
                        // Note: Progress bar not shown for mmap as it's very fast
                        for (_, hasher) in &mut hashers {
                            hasher.update(&mmap[..]);
                        }
                    }
                    Err(_) => {
                        // Fall back to buffered reading if mmap fails
                        if should_show_progress {
                            self.hash_multiple_with_buffered_io_progress(
                                &mut hashers,
                                file,
                                path,
                                file_size,
                            )?;
                        } else {
                            self.hash_multiple_with_buffered_io(&mut hashers, file, path)?;
                        }
                    }
                }
            } else {
                // Use buffered reading for large files (>2GB) or empty files
                if should_show_progress {
                    self.hash_multiple_with_buffered_io_progress(
                        &mut hashers,
                        file,
                        path,
                        file_size,
                    )?;
                } else {
                    self.hash_multiple_with_buffered_io(&mut hashers, file, path)?;
                }
            }
        }
        #[cfg(not(feature = "mmap"))]
        {
            if should_show_progress {
                self.hash_multiple_with_buffered_io_progress(&mut hashers, file, path, file_size)?;
            } else {
                self.hash_multiple_with_buffered_io(&mut hashers, file, path)?;
            }
        }

        // Finalize all hashes and collect results
        let mut results = Vec::new();
        for (algorithm, hasher) in hashers {
            let hash_bytes = hasher.finalize();
            let hash_hex = bytes_to_hex(&hash_bytes);

            results.push(HashResult {
                algorithm,
                hash: hash_hex,
                file_path: path.to_path_buf(),
            });
        }

        Ok(results)
    }

    /// Helper method to hash a file with multiple hashers using buffered I/O
    fn hash_multiple_with_buffered_io(
        &self,
        hashers: &mut [(String, Box<dyn Hasher>)],
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

            // Update all hashers with the same data
            for (_, hasher) in hashers.iter_mut() {
                hasher.update(&buffer[..bytes_read]);
            }
        }

        Ok(())
    }

    /// Helper method to hash a file with multiple hashers using buffered I/O with progress bar
    fn hash_multiple_with_buffered_io_progress(
        &self,
        hashers: &mut [(String, Box<dyn Hasher>)],
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

            // Update all hashers with the same data
            for (_, hasher) in hashers.iter_mut() {
                hasher.update(&buffer[..bytes_read]);
            }

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
}

impl Default for HashComputer {
    fn default() -> Self {
        Self::new()
    }
}
