//! Recursive directory scanning.
// Handles recursive directory traversal and hash computation

use crate::database::DatabaseHandler;
use crate::error::HashUtilityError;
use crate::hash::HashComputer;
use crate::ignore_handler::IgnoreHandler;
use crate::operation::{LegacyProgress as ProgressBar, LegacyProgressStyle as ProgressStyle};
use crate::path_utils;
use crossbeam_channel::{bounded, Sender};
use jwalk::WalkDir;
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Backward-compatible error name for directory scan operations.
pub type ScanError = HashUtilityError;

/// Statistics collected during a directory scan
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanStats {
    /// Number of files hashed successfully.
    pub files_processed: usize,
    /// Number of files that could not be processed.
    pub files_failed: usize,
    /// Sum of sizes of successfully processed files.
    pub total_bytes: u64,
    #[serde(serialize_with = "serialize_duration")]
    /// Elapsed scan time, serialized as seconds.
    pub duration: Duration,
}

// Helper function to serialize Duration as seconds
fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_f64(duration.as_secs_f64())
}

use crate::database::DatabaseFormat;

/// Engine for scanning directories and generating hash databases
pub struct ScanEngine {
    computer: HashComputer,
    parallel: bool,
    fast_mode: bool,
    use_ignore: bool,
    format: DatabaseFormat,
}

impl ScanEngine {
    /// Create a new ScanEngine with default settings
    pub fn new() -> Self {
        Self {
            computer: HashComputer::new(),
            parallel: false,
            fast_mode: false,
            use_ignore: true,
            format: DatabaseFormat::Standard,
        }
    }

    /// Create a new ScanEngine with parallel processing enabled
    pub fn with_parallel(parallel: bool) -> Self {
        Self {
            computer: HashComputer::new(),
            parallel,
            fast_mode: false,
            use_ignore: true,
            format: DatabaseFormat::Standard,
        }
    }

    /// Enable or disable fast mode for large file hashing
    pub fn with_fast_mode(mut self, fast_mode: bool) -> Self {
        self.fast_mode = fast_mode;
        self
    }

    /// Enable or disable .hashignore file support
    pub fn with_ignore(mut self, use_ignore: bool) -> Self {
        self.use_ignore = use_ignore;
        self
    }

    /// Set the output format
    pub fn with_format(mut self, format: DatabaseFormat) -> Self {
        self.format = format;
        self
    }

    /// Scan a directory recursively and write hash database to output file
    ///
    /// # Arguments
    /// * `root` - Root directory to scan
    /// * `algorithm` - Hash algorithm to use
    /// * `output` - Output file path for hash database
    ///
    /// # Returns
    /// Statistics about the scan operation
    pub fn scan_directory(
        &self,
        root: &Path,
        algorithm: &str,
        output: &Path,
    ) -> Result<ScanStats, ScanError> {
        let start_time = Instant::now();

        // Canonicalize root directory for consistent path handling
        let canonical_root = root.canonicalize().map_err(|e| {
            HashUtilityError::from_io_error(e, "scanning directory", Some(root.to_path_buf()))
        })?;

        // Get absolute path of output file to exclude it from scan
        // We need to get the absolute path before the file exists
        let output_absolute = if output.is_absolute() {
            output.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(output))
                .unwrap_or_else(|_| output.to_path_buf())
        };

        // Collect all files in the directory tree (only for sequential mode)
        println!("Scanning directory: {}", root.display());
        let files = if !self.parallel {
            self.collect_files_with_exclusion(root, Some(&output_absolute))?
        } else {
            // For parallel mode, we don't pre-collect files
            Vec::new()
        };

        if !self.parallel {
            println!("Found {} files to process", files.len());
        }

        if self.fast_mode {
            println!("Fast mode enabled: sampling first, middle, and last 100MB of large files");
        }

        if self.parallel {
            self.scan_parallel(
                &files,
                algorithm,
                output,
                &canonical_root,
                &output_absolute,
                start_time,
            )
        } else {
            self.scan_sequential(&files, algorithm, output, &canonical_root, start_time)
        }
    }

    /// Sequential scan implementation
    fn scan_sequential(
        &self,
        files: &[PathBuf],
        algorithm: &str,
        output: &Path,
        canonical_root: &Path,
        start_time: Instant,
    ) -> Result<ScanStats, ScanError> {
        // Open output file for writing
        let output_file = File::create(output).map_err(|e| {
            HashUtilityError::from_io_error(e, "creating output file", Some(output.to_path_buf()))
        })?;
        let mut writer = BufWriter::new(output_file);

        // Write hashdeep header if using hashdeep format
        if self.format == DatabaseFormat::Hashdeep {
            DatabaseHandler::write_hashdeep_header(&mut writer, &[algorithm.to_string()]).map_err(
                |e| {
                    HashUtilityError::from_io_error(
                        e,
                        "writing hashdeep header",
                        Some(output.to_path_buf()),
                    )
                },
            )?;
        }

        // Track statistics
        let mut files_processed = 0;
        let mut files_failed = 0;
        let mut files_skipped = 0;
        let mut total_bytes = 0u64;

        // Create progress bar
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({percent}%) | Processed: {msg}")
                .unwrap()
                .progress_chars("=>-")
        );

        // Process each file
        for file_path in files.iter() {
            // Update progress bar with counts instead of filename to avoid encoding issues
            pb.set_message(format!(
                "{} OK, {} failed, {} skipped",
                files_processed, files_failed, files_skipped
            ));

            // Check if file still exists and is accessible before processing
            let metadata_check = fs::metadata(file_path);
            if metadata_check.is_err() {
                files_skipped += 1;
                pb.inc(1);
                continue;
            }

            // Compute hash for the file (using fast mode if enabled)
            let hash_result = if self.fast_mode {
                self.computer.compute_hash_fast(file_path, algorithm)
            } else {
                self.computer.compute_hash(file_path, algorithm)
            };

            match hash_result {
                Ok(result) => {
                    // Try to get relative path for cleaner database entries
                    // Use cached version since canonical_root is already canonicalized
                    let path_to_write =
                        match path_utils::get_relative_path_cached(file_path, canonical_root) {
                            Ok(rel_path) => rel_path,
                            Err(_) => file_path.clone(),
                        };

                    // Get file size for hashdeep format
                    let file_size = fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);

                    // Write hash entry to database with metadata
                    let write_result = match self.format {
                        DatabaseFormat::Standard => DatabaseHandler::write_entry(
                            &mut writer,
                            &result.hash,
                            algorithm,
                            self.fast_mode,
                            &path_to_write,
                        ),
                        DatabaseFormat::Hashdeep => DatabaseHandler::write_hashdeep_entry(
                            &mut writer,
                            file_size,
                            &[result.hash.clone()],
                            &path_to_write,
                        ),
                    };

                    if let Err(e) = write_result {
                        eprintln!(
                            "Warning: Failed to write entry for {}: {}",
                            file_path.display(),
                            e
                        );
                        files_failed += 1;
                    } else {
                        files_processed += 1;
                        total_bytes += file_size;
                    }
                }
                Err(e) => {
                    // Log error but continue processing
                    eprintln!("Warning: Failed to hash {}: {}", file_path.display(), e);
                    files_failed += 1;
                }
            }

            pb.inc(1);
        }

        let duration = start_time.elapsed();

        // Clear progress bar and display summary
        pb.finish_and_clear();

        println!("\nScan complete!");
        println!("Files processed: {}", files_processed);
        println!("Files failed: {}", files_failed);
        println!("Files skipped: {}", files_skipped);
        println!(
            "Total bytes: {} ({:.2} MB)",
            total_bytes,
            total_bytes as f64 / 1_048_576.0
        );
        println!("Duration: {:.2}s", duration.as_secs_f64());

        // Calculate and display throughput
        if duration.as_secs_f64() > 0.0 {
            let throughput_mbps = (total_bytes as f64 / 1_048_576.0) / duration.as_secs_f64();
            println!("Throughput: {:.2} MB/s", throughput_mbps);
        }

        println!("Output written to: {}", output.display());

        Ok(ScanStats {
            files_processed,
            files_failed: files_failed + files_skipped,
            total_bytes,
            duration,
        })
    }

    /// Parallel scan implementation using producer-consumer pattern with jwalk and crossbeam-channel
    fn scan_parallel(
        &self,
        _files: &[PathBuf],
        algorithm: &str,
        output: &Path,
        canonical_root: &Path,
        output_absolute: &Path,
        start_time: Instant,
    ) -> Result<ScanStats, ScanError> {
        // Thread-safe counters for progress tracking
        let files_processed = Arc::new(Mutex::new(0usize));
        let files_failed = Arc::new(Mutex::new(0usize));
        let files_skipped = Arc::new(Mutex::new(0usize));
        let total_bytes = Arc::new(Mutex::new(0u64));

        // Create progress bar (we'll update the style once discovery is complete)
        let pb = ProgressBar::new(0);
        // Start with "Counting..." style
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] Counting... {pos} files found | Processing: {msg}")
                .unwrap()
                .progress_chars("=>-"),
        );

        // Create bounded channel with backpressure (buffer size: 10000 entries)
        // Larger buffer helps with very large directory scans
        let (sender, receiver) = bounded::<PathBuf>(10000);

        // Track total files discovered
        let total_files_discovered = Arc::new(Mutex::new(0usize));
        let discovery_complete = Arc::new(Mutex::new(false));

        // Capture fast_mode for use in closure
        let fast_mode = self.fast_mode;

        // Clone canonical_root and output_absolute for the walker thread
        let walker_root = canonical_root.to_path_buf();
        let use_ignore = self.use_ignore;
        let output_to_exclude = output_absolute.to_path_buf();

        // Clone for walker thread
        let total_files_discovered_walker = Arc::clone(&total_files_discovered);
        let discovery_complete_walker = Arc::clone(&discovery_complete);
        let pb_walker = pb.clone();

        // Spawn walker thread using jwalk to traverse directories
        let walker_handle = thread::spawn(move || {
            let result = Self::walk_directory_streaming(
                &walker_root,
                sender,
                use_ignore,
                Some(&output_to_exclude),
                Arc::clone(&total_files_discovered_walker),
            );

            // Mark discovery as complete and update progress bar with total and new style
            let total = *total_files_discovered_walker.lock().unwrap();
            pb_walker.set_length(total as u64);
            pb_walker.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({percent}%) | Processed: {msg}")
                    .unwrap()
                    .progress_chars("=>-")
            );
            *discovery_complete_walker.lock().unwrap() = true;

            result
        });

        // Clone Arc references for use in parallel closure
        let files_processed_clone = Arc::clone(&files_processed);
        let files_failed_clone = Arc::clone(&files_failed);
        let files_skipped_clone = Arc::clone(&files_skipped);
        let total_bytes_clone = Arc::clone(&total_bytes);
        let pb_clone = pb.clone();
        let canonical_root_clone = canonical_root.to_path_buf();

        // Use rayon's par_bridge to consume from channel in parallel
        // This starts hashing immediately as files are discovered
        let results: Vec<_> = receiver
            .into_iter()
            .par_bridge()
            .filter_map(|file_path| {
                // Check if file still exists and is accessible before processing
                let metadata_check = fs::metadata(&file_path);
                if metadata_check.is_err() {
                    let mut skipped = files_skipped_clone.lock().unwrap();
                    *skipped += 1;
                    pb_clone.inc(1);
                    return None;
                }

                // Update progress bar with counts instead of filename to avoid encoding issues
                let processed = files_processed_clone.lock().unwrap();
                let failed = files_failed_clone.lock().unwrap();
                let skipped = files_skipped_clone.lock().unwrap();
                pb_clone.set_message(format!(
                    "{} OK, {} failed, {} skipped",
                    *processed, *failed, *skipped
                ));
                drop(processed);
                drop(failed);
                drop(skipped);

                // Compute hash for the file (using fast mode if enabled)
                let computer = HashComputer::new();
                let hash_result = if fast_mode {
                    computer.compute_hash_fast(&file_path, algorithm)
                } else {
                    computer.compute_hash(&file_path, algorithm)
                };

                let result = match hash_result {
                    Ok(result) => {
                        // Try to get relative path for cleaner database entries
                        // Use cached version since canonical_root_clone is already canonicalized
                        let path_to_write = match path_utils::get_relative_path_cached(
                            &file_path,
                            &canonical_root_clone,
                        ) {
                            Ok(rel_path) => rel_path,
                            Err(_) => file_path.clone(),
                        };

                        // Preserve the size before replacing the absolute path
                        // with its manifest-relative representation.
                        let file_size = fs::metadata(&file_path)
                            .map(|metadata| metadata.len())
                            .unwrap_or(0);
                        if file_size > 0 {
                            let mut bytes = total_bytes_clone.lock().unwrap();
                            *bytes += file_size;
                        }

                        // Update success counter
                        let mut processed = files_processed_clone.lock().unwrap();
                        *processed += 1;

                        Some((result.hash, path_to_write, file_size))
                    }
                    Err(e) => {
                        // Log error but continue processing
                        eprintln!("Warning: Failed to hash {}: {}", file_path.display(), e);

                        // Update failure counter
                        let mut failed = files_failed_clone.lock().unwrap();
                        *failed += 1;

                        None
                    }
                };

                pb_clone.inc(1);
                result
            })
            .collect();

        // Wait for walker thread to complete
        // Note: The walker thread should already be done since we consumed all items from the channel
        match walker_handle.join() {
            Ok(walk_result) => {
                if let Err(e) = walk_result {
                    eprintln!("Warning: Walker thread encountered error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Warning: Walker thread panicked: {:?}", e);
            }
        }

        let duration = start_time.elapsed();

        // Clear progress bar
        pb.finish_and_clear();

        // Write all results to output file
        let output_file = File::create(output).map_err(|e| {
            HashUtilityError::from_io_error(e, "creating output file", Some(output.to_path_buf()))
        })?;
        let mut writer = BufWriter::new(output_file);

        // Write hashdeep header if using hashdeep format
        if self.format == DatabaseFormat::Hashdeep {
            if let Err(e) =
                DatabaseHandler::write_hashdeep_header(&mut writer, &[algorithm.to_string()])
            {
                eprintln!("Warning: Failed to write hashdeep header: {}", e);
            }
        }

        for result in results.iter() {
            let write_result = match self.format {
                DatabaseFormat::Standard => DatabaseHandler::write_entry(
                    &mut writer,
                    &result.0,
                    algorithm,
                    fast_mode,
                    &result.1,
                ),
                DatabaseFormat::Hashdeep => DatabaseHandler::write_hashdeep_entry(
                    &mut writer,
                    result.2,
                    &[result.0.clone()],
                    &result.1,
                ),
            };

            if let Err(e) = write_result {
                eprintln!("Warning: Failed to write entry: {}", e);
            }
        }

        // Flush the writer to ensure all data is written
        writer.flush().map_err(|e| {
            HashUtilityError::from_io_error(e, "flushing output file", Some(output.to_path_buf()))
        })?;

        // Extract final statistics
        let final_processed = *files_processed.lock().unwrap();
        let final_failed = *files_failed.lock().unwrap();
        let final_skipped = *files_skipped.lock().unwrap();
        let final_bytes = *total_bytes.lock().unwrap();

        // Display summary
        println!("\nScan complete!");
        println!("Files processed: {}", final_processed);
        println!("Files failed: {}", final_failed);
        println!("Files skipped: {}", final_skipped);
        println!(
            "Total bytes: {} ({:.2} MB)",
            final_bytes,
            final_bytes as f64 / 1_048_576.0
        );
        println!("Duration: {:.2}s", duration.as_secs_f64());

        // Calculate and display throughput
        if duration.as_secs_f64() > 0.0 {
            let throughput_mbps = (final_bytes as f64 / 1_048_576.0) / duration.as_secs_f64();
            println!("Throughput: {:.2} MB/s", throughput_mbps);
        }

        println!("Output written to: {}", output.display());

        Ok(ScanStats {
            files_processed: final_processed,
            files_failed: final_failed + final_skipped,
            total_bytes: final_bytes,
            duration,
        })
    }

    /// Walk directory using jwalk and send file paths to channel as they're discovered
    /// This is the producer in the producer-consumer pattern
    fn walk_directory_streaming(
        root: &Path,
        sender: Sender<PathBuf>,
        use_ignore: bool,
        exclude_file: Option<&Path>,
        total_files_discovered: Arc<Mutex<usize>>,
    ) -> Result<(), ScanError> {
        // Load .hashignore patterns if enabled
        let ignore_handler = if use_ignore {
            match IgnoreHandler::new(root) {
                Ok(handler) => Some(Arc::new(handler)),
                Err(e) => {
                    eprintln!("Warning: Failed to load .hashignore: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Canonicalize exclude path once before the loop to avoid redundant calls
        let canonical_exclude = exclude_file.and_then(|p| p.canonicalize().ok());

        // Prune ignored directories before traversal so directory-only patterns
        // also exclude every descendant in the parallel walker.
        let mut walker = WalkDir::new(root)
            .parallelism(jwalk::Parallelism::RayonNewPool(0)) // 0 = use default thread count
            .skip_hidden(false) // Don't skip hidden files
            .follow_links(false);
        if let Some(handler) = ignore_handler.clone() {
            let root = root.to_path_buf();
            walker = walker.process_read_dir(move |_depth, _dir, _state, children| {
                for child_result in children.iter_mut() {
                    let Ok(child) = child_result else {
                        continue;
                    };
                    if !child.file_type.is_dir() {
                        continue;
                    }
                    let child_path = child.path();
                    if child_path
                        .strip_prefix(&root)
                        .is_ok_and(|relative| handler.should_ignore(relative, true))
                    {
                        child.read_children_path = None;
                    }
                }
            });
        }

        for entry_result in walker {
            match entry_result {
                Ok(entry) => {
                    let path = entry.path();

                    // Only process regular files
                    if !entry.file_type().is_file() {
                        continue;
                    }

                    // Check if this is the excluded file
                    if let Some(ref exclude_canonical) = canonical_exclude {
                        // Compare canonical paths (only canonicalize current path once)
                        if let Ok(canonical_path) = path.canonicalize() {
                            if &canonical_path == exclude_canonical {
                                continue;
                            }
                        }
                    }

                    // Check if this path should be ignored
                    if let Some(ref handler) = ignore_handler {
                        if let Ok(rel_path) = path.strip_prefix(root) {
                            if handler.should_ignore(rel_path, false) {
                                continue;
                            }
                        }
                    }

                    // Send file path to channel
                    // If channel is full, this will block (backpressure)
                    if let Err(_) = sender.send(path) {
                        // Receiver has been dropped, stop walking
                        break;
                    }

                    // Track total files discovered
                    let mut total = total_files_discovered.lock().unwrap();
                    *total += 1;
                }
                Err(e) => {
                    // Log errors during directory scans without stopping
                    eprintln!("Warning: Error walking directory: {}", e);
                }
            }
        }

        // Channel will be closed when sender is dropped
        Ok(())
    }

    /// Recursively collect all regular files in a directory tree
    ///
    /// # Arguments
    /// * `root` - Root directory to traverse
    ///
    /// # Returns
    /// Vector of all file paths found
    #[allow(dead_code)]
    fn collect_files(&self, root: &Path) -> Result<Vec<PathBuf>, ScanError> {
        self.collect_files_with_exclusion(root, None)
    }

    /// Recursively collect all regular files in a directory tree, excluding a specific file
    ///
    /// # Arguments
    /// * `root` - Root directory to traverse
    /// * `exclude_file` - Optional file path to exclude from collection
    ///
    /// # Returns
    /// Vector of all file paths found
    fn collect_files_with_exclusion(
        &self,
        root: &Path,
        exclude_file: Option<&Path>,
    ) -> Result<Vec<PathBuf>, ScanError> {
        let mut files = Vec::new();

        // Load .hashignore patterns if enabled
        let ignore_handler = if self.use_ignore {
            match IgnoreHandler::new(root) {
                Ok(handler) => Some(handler),
                Err(e) => {
                    eprintln!("Warning: Failed to load .hashignore: {}", e);
                    None
                }
            }
        } else {
            None
        };

        self.collect_files_recursive(
            root,
            root,
            &mut files,
            ignore_handler.as_ref(),
            exclude_file,
        )?;
        Ok(files)
    }

    /// Helper function for recursive file collection
    fn collect_files_recursive(
        &self,
        root: &Path,
        dir: &Path,
        files: &mut Vec<PathBuf>,
        ignore_handler: Option<&IgnoreHandler>,
        exclude_file: Option<&Path>,
    ) -> Result<(), ScanError> {
        self.collect_files_recursive_with_cache(
            root,
            dir,
            files,
            ignore_handler,
            exclude_file,
            &mut None,
        )
    }

    /// Helper function for recursive file collection with cached exclude path
    fn collect_files_recursive_with_cache(
        &self,
        root: &Path,
        dir: &Path,
        files: &mut Vec<PathBuf>,
        ignore_handler: Option<&IgnoreHandler>,
        exclude_file: Option<&Path>,
        canonical_exclude_cache: &mut Option<PathBuf>,
    ) -> Result<(), ScanError> {
        // Check if path exists and is accessible
        if !dir.exists() {
            return Err(HashUtilityError::DirectoryNotFound {
                path: dir.to_path_buf(),
            });
        }

        // Canonicalize exclude path once on first call
        if canonical_exclude_cache.is_none() && exclude_file.is_some() {
            *canonical_exclude_cache = exclude_file.and_then(|p| p.canonicalize().ok());
        }

        // Read directory entries
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                // Log permission errors but don't stop the scan (Requirement 2.4)
                eprintln!("Warning: Cannot read directory {}: {}", dir.display(), e);
                return Ok(());
            }
        };

        // Process each entry
        for entry_result in entries {
            let entry = match entry_result {
                Ok(entry) => entry,
                Err(e) => {
                    // Log errors during directory scans without stopping (Requirement 2.4)
                    eprintln!("Warning: Cannot read directory entry: {}", e);
                    continue;
                }
            };

            let path = entry.path();

            // Get metadata to determine if it's a file or directory
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(e) => {
                    // Log errors during directory scans without stopping (Requirement 2.4)
                    eprintln!(
                        "Warning: Cannot read metadata for {}: {}",
                        path.display(),
                        e
                    );
                    continue;
                }
            };

            let is_dir = metadata.is_dir();

            // Check if this is the excluded file using cached canonical path
            if let Some(ref exclude_canonical) = canonical_exclude_cache {
                if let Ok(canonical_path) = path.canonicalize() {
                    if &canonical_path == exclude_canonical {
                        // Skip the excluded file
                        continue;
                    }
                }
            }

            // Check if this path should be ignored
            if let Some(handler) = ignore_handler {
                // Get relative path for ignore matching
                if let Ok(rel_path) = path.strip_prefix(root) {
                    if handler.should_ignore(rel_path, is_dir) {
                        // Skip ignored files and directories
                        continue;
                    }
                }
            }

            if metadata.is_file() {
                // Add regular files to the list
                files.push(path);
            } else if is_dir {
                // Recursively process subdirectories with cached exclude path
                if let Err(e) = self.collect_files_recursive_with_cache(
                    root,
                    &path,
                    files,
                    ignore_handler,
                    exclude_file,
                    canonical_exclude_cache,
                ) {
                    // Log error but continue with other directories (Requirement 2.4)
                    eprintln!(
                        "Warning: Error processing directory {}: {}",
                        path.display(),
                        e
                    );
                }
            }
            // Skip symbolic links and other special files
        }

        Ok(())
    }
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_scan_single_file() {
        // Create a temporary directory with a single file
        let test_dir = "test_scan_single";
        fs::create_dir_all(test_dir).unwrap();

        let test_file = format!("{}/test.txt", test_dir);
        fs::write(&test_file, b"hello world").unwrap();

        // Scan the directory
        let engine = ScanEngine::new();
        let output = format!("{}/hashes.txt", test_dir);
        let stats = engine
            .scan_directory(Path::new(test_dir), "sha256", Path::new(&output))
            .unwrap();

        // Verify statistics
        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.files_failed, 0);
        assert!(stats.total_bytes > 0);

        // Verify output file exists and contains the hash
        assert!(Path::new(&output).exists());
        let content = fs::read_to_string(&output).unwrap();
        assert!(content.contains("test.txt"));
        assert!(
            content.contains("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_scan_multiple_files() {
        // Create a temporary directory with multiple files
        let test_dir = "test_scan_multiple";
        fs::create_dir_all(test_dir).unwrap();

        fs::write(format!("{}/file1.txt", test_dir), b"content1").unwrap();
        fs::write(format!("{}/file2.txt", test_dir), b"content2").unwrap();
        fs::write(format!("{}/file3.txt", test_dir), b"content3").unwrap();

        // Scan the directory
        let engine = ScanEngine::new();
        let output = format!("{}/hashes.txt", test_dir);
        let stats = engine
            .scan_directory(Path::new(test_dir), "md5", Path::new(&output))
            .unwrap();

        // Verify statistics
        assert_eq!(stats.files_processed, 3);
        assert_eq!(stats.files_failed, 0);

        // Verify output file contains all files
        let content = fs::read_to_string(&output).unwrap();
        assert!(content.contains("file1.txt"));
        assert!(content.contains("file2.txt"));
        assert!(content.contains("file3.txt"));

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_scan_nested_directories() {
        // Create a nested directory structure
        let test_dir = "test_scan_nested";
        fs::create_dir_all(format!("{}/subdir1/subdir2", test_dir)).unwrap();

        fs::write(format!("{}/root.txt", test_dir), b"root").unwrap();
        fs::write(format!("{}/subdir1/sub1.txt", test_dir), b"sub1").unwrap();
        fs::write(format!("{}/subdir1/subdir2/sub2.txt", test_dir), b"sub2").unwrap();

        // Scan the directory
        let engine = ScanEngine::new();
        let output = format!("{}/hashes.txt", test_dir);
        let stats = engine
            .scan_directory(Path::new(test_dir), "sha256", Path::new(&output))
            .unwrap();

        // Verify all files were found
        assert_eq!(stats.files_processed, 3);
        assert_eq!(stats.files_failed, 0);

        // Verify output contains all files
        let content = fs::read_to_string(&output).unwrap();
        assert!(content.contains("root.txt"));
        assert!(content.contains("sub1.txt"));
        assert!(content.contains("sub2.txt"));

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_scan_empty_directory() {
        // Create an empty directory
        let test_dir = "test_scan_empty";
        fs::create_dir_all(test_dir).unwrap();

        // Scan the directory
        let engine = ScanEngine::new();
        let output = format!("{}/hashes.txt", test_dir);
        let stats = engine
            .scan_directory(Path::new(test_dir), "sha256", Path::new(&output))
            .unwrap();

        // Verify no files were processed
        assert_eq!(stats.files_processed, 0);
        assert_eq!(stats.files_failed, 0);

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_scan_nonexistent_directory() {
        let engine = ScanEngine::new();
        let result = engine.scan_directory(
            Path::new("nonexistent_directory_xyz"),
            "sha256",
            Path::new("output.txt"),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_collect_files_recursive() {
        // Create a test directory structure
        let test_dir = "test_collect_files";
        fs::create_dir_all(format!("{}/dir1/dir2", test_dir)).unwrap();

        fs::write(format!("{}/file1.txt", test_dir), b"test").unwrap();
        fs::write(format!("{}/dir1/file2.txt", test_dir), b"test").unwrap();
        fs::write(format!("{}/dir1/dir2/file3.txt", test_dir), b"test").unwrap();

        // Collect files
        let engine = ScanEngine::new();
        let files = engine.collect_files(Path::new(test_dir)).unwrap();

        // Verify all files were collected
        assert_eq!(files.len(), 3);

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_scan_parallel_mode() {
        // Create a temporary directory with multiple files
        let test_dir = "test_scan_parallel";
        fs::create_dir_all(test_dir).unwrap();

        fs::write(format!("{}/file1.txt", test_dir), b"content1").unwrap();
        fs::write(format!("{}/file2.txt", test_dir), b"content2").unwrap();
        fs::write(format!("{}/file3.txt", test_dir), b"content3").unwrap();
        fs::write(format!("{}/file4.txt", test_dir), b"content4").unwrap();

        // Scan the directory with parallel mode enabled
        let engine = ScanEngine::with_parallel(true);
        let output = format!("{}/hashes_parallel.txt", test_dir);
        let stats = engine
            .scan_directory(Path::new(test_dir), "sha256", Path::new(&output))
            .unwrap();

        // Verify statistics
        assert_eq!(stats.files_processed, 4);
        assert_eq!(stats.files_failed, 0);

        // Verify output file contains all files
        let content = fs::read_to_string(&output).unwrap();
        assert!(content.contains("file1.txt"));
        assert!(content.contains("file2.txt"));
        assert!(content.contains("file3.txt"));
        assert!(content.contains("file4.txt"));

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_scan_parallel_vs_sequential() {
        // Create separate temporary directories for sequential and parallel tests
        let test_dir_seq = "test_scan_seq";
        let test_dir_par = "test_scan_par";

        // Setup sequential test directory
        fs::create_dir_all(test_dir_seq).unwrap();
        fs::write(format!("{}/file1.txt", test_dir_seq), b"test data 1").unwrap();
        fs::write(format!("{}/file2.txt", test_dir_seq), b"test data 2").unwrap();
        fs::write(format!("{}/file3.txt", test_dir_seq), b"test data 3").unwrap();

        // Setup parallel test directory with identical content
        fs::create_dir_all(test_dir_par).unwrap();
        fs::write(format!("{}/file1.txt", test_dir_par), b"test data 1").unwrap();
        fs::write(format!("{}/file2.txt", test_dir_par), b"test data 2").unwrap();
        fs::write(format!("{}/file3.txt", test_dir_par), b"test data 3").unwrap();

        // Scan sequentially
        let engine_seq = ScanEngine::with_parallel(false);
        let output_seq = "output_seq.txt";
        let stats_seq = engine_seq
            .scan_directory(Path::new(test_dir_seq), "sha256", Path::new(output_seq))
            .unwrap();

        // Scan in parallel
        let engine_par = ScanEngine::with_parallel(true);
        let output_par = "output_par.txt";
        let stats_par = engine_par
            .scan_directory(Path::new(test_dir_par), "sha256", Path::new(output_par))
            .unwrap();

        // Verify both produce the same number of results
        assert_eq!(stats_seq.files_processed, stats_par.files_processed);
        assert_eq!(stats_seq.files_failed, stats_par.files_failed);
        assert_eq!(stats_seq.total_bytes, stats_par.total_bytes);

        // Read both output files
        let content_seq = fs::read_to_string(output_seq).unwrap();
        let content_par = fs::read_to_string(output_par).unwrap();

        // Parse lines and sort them (parallel may produce different order)
        let mut lines_seq: Vec<&str> = content_seq.lines().collect();
        let mut lines_par: Vec<&str> = content_par.lines().collect();
        lines_seq.sort();
        lines_par.sort();

        // Both should have the same hashes (paths will differ but hashes should match)
        assert_eq!(lines_seq.len(), lines_par.len());

        // Extract and compare hashes (first part before two spaces)
        let hashes_seq: Vec<&str> = lines_seq
            .iter()
            .map(|line| line.split("  ").next().unwrap())
            .collect();
        let hashes_par: Vec<&str> = lines_par
            .iter()
            .map(|line| line.split("  ").next().unwrap())
            .collect();

        assert_eq!(hashes_seq, hashes_par);

        // Cleanup
        fs::remove_dir_all(test_dir_seq).unwrap();
        fs::remove_dir_all(test_dir_par).unwrap();
        fs::remove_file(output_seq).unwrap();
        fs::remove_file(output_par).unwrap();
    }

    #[test]
    fn test_walk_directory_streaming_skips_ignored_directory_patterns() {
        let temporary = tempfile::tempdir().unwrap();
        fs::create_dir_all(temporary.path().join("A/sub")).unwrap();
        fs::create_dir_all(temporary.path().join("B")).unwrap();
        fs::write(temporary.path().join(".hashignore"), b"A/\n").unwrap();
        fs::write(temporary.path().join("A/file1.txt"), b"one").unwrap();
        fs::write(temporary.path().join("A/sub/file2.txt"), b"two").unwrap();
        fs::write(temporary.path().join("B/file3.txt"), b"three").unwrap();

        let (sender, receiver) = bounded::<PathBuf>(16);
        let discovered = Arc::new(Mutex::new(0));
        ScanEngine::walk_directory_streaming(
            temporary.path(),
            sender,
            true,
            None,
            Arc::clone(&discovered),
        )
        .unwrap();
        let files: Vec<_> = receiver.iter().collect();

        assert_eq!(files.len(), 1);
        assert_eq!(*discovered.lock().unwrap(), 1);
        assert!(files[0].ends_with(Path::new("B").join("file3.txt")));
    }
}
