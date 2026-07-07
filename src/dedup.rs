// Dedup engine module
// Finds duplicate files within a directory by comparing hash values

use crate::error::HashUtilityError;
use crate::hash::HashComputer;
use crate::ignore_handler::IgnoreHandler;
use crossbeam_channel::bounded;
use indicatif::{ProgressBar, ProgressStyle};
use jwalk::WalkDir;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Statistics collected during a dedup scan
#[derive(Debug, Clone, serde::Serialize)]
pub struct DedupStats {
    pub files_scanned: usize,
    pub files_failed: usize,
    pub total_bytes: u64,
    pub duplicate_groups: usize,
    pub duplicate_files: usize,
    pub wasted_space: u64,
    #[serde(serialize_with = "serialize_duration")]
    pub duration: Duration,
}

// Helper function to serialize Duration as seconds
fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_f64(duration.as_secs_f64())
}

/// Report of duplicate files found in a directory
#[derive(Debug, Clone, serde::Serialize)]
pub struct DedupReport {
    pub stats: DedupStats,
    pub duplicate_groups: Vec<DuplicateGroupWithSize>,
}

/// Duplicate group with file size information
#[derive(Debug, Clone, serde::Serialize)]
pub struct DuplicateGroupWithSize {
    pub hash: String,
    pub paths: Vec<PathBuf>,
    pub count: usize,
    pub file_size: u64,
    pub wasted_space: u64, // (count - 1) * file_size
}

impl DedupReport {
    /// Display the dedup report in plain text format
    #[allow(dead_code)]
    pub fn display(&self) {
        println!("\n=== Duplicate Files Report ===\n");

        // Summary section
        println!("Summary:");
        println!("  Files scanned:     {}", self.stats.files_scanned);
        println!("  Files failed:      {}", self.stats.files_failed);
        println!(
            "  Total bytes:       {} ({:.2} MB)",
            self.stats.total_bytes,
            self.stats.total_bytes as f64 / 1_048_576.0
        );
        println!("  Duplicate groups:  {}", self.stats.duplicate_groups);
        println!("  Duplicate files:   {}", self.stats.duplicate_files);
        println!(
            "  Wasted space:      {} ({:.2} MB)",
            self.stats.wasted_space,
            self.stats.wasted_space as f64 / 1_048_576.0
        );
        println!(
            "  Duration:          {:.2}s",
            self.stats.duration.as_secs_f64()
        );

        // Calculate and display throughput
        if self.stats.duration.as_secs_f64() > 0.0 {
            let throughput_mbps =
                (self.stats.total_bytes as f64 / 1_048_576.0) / self.stats.duration.as_secs_f64();
            println!("  Throughput:        {:.2} MB/s", throughput_mbps);
        }

        // Duplicate groups section (sorted by wasted space, largest first)
        if !self.duplicate_groups.is_empty() {
            println!("\nDuplicate Groups (sorted by wasted space):");
            for group in &self.duplicate_groups {
                println!(
                    "\n  Hash: {} ({} files, {} bytes each, {} bytes wasted)",
                    group.hash, group.count, group.file_size, group.wasted_space
                );
                for path in &group.paths {
                    println!("    {}", path.display());
                }
            }
        } else {
            println!("\nNo duplicate files found.");
        }

        println!();
    }

    /// Format the dedup report as JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        #[derive(serde::Serialize)]
        struct JsonOutput {
            metadata: Metadata,
            stats: DedupStats,
            duplicate_groups: Vec<DuplicateGroupJson>,
        }

        #[derive(serde::Serialize)]
        struct Metadata {
            timestamp: String,
        }

        #[derive(serde::Serialize)]
        struct DuplicateGroupJson {
            hash: String,
            count: usize,
            file_size: u64,
            wasted_space: u64,
            paths: Vec<String>,
        }

        let output = JsonOutput {
            metadata: Metadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
            stats: self.stats.clone(),
            duplicate_groups: self
                .duplicate_groups
                .iter()
                .map(|dg| DuplicateGroupJson {
                    hash: dg.hash.clone(),
                    count: dg.count,
                    file_size: dg.file_size,
                    wasted_space: dg.wasted_space,
                    paths: dg.paths.iter().map(|p| p.display().to_string()).collect(),
                })
                .collect(),
        };

        serde_json::to_string_pretty(&output)
    }
}

/// Engine for finding duplicate files in a directory
pub struct DedupEngine {
    computer: HashComputer,
    fast_mode: bool,
    parallel: bool,
    quiet: bool,
}

impl DedupEngine {
    /// Create a new DedupEngine with default settings
    /// Always uses BLAKE3 algorithm (fast and secure)
    pub fn new() -> Self {
        Self {
            computer: HashComputer::new(),
            fast_mode: false,
            parallel: true, // Default to parallel for better performance
            quiet: false,
        }
    }

    /// Enable or disable fast mode for large file hashing
    pub fn with_fast_mode(mut self, fast_mode: bool) -> Self {
        self.fast_mode = fast_mode;
        self
    }

    /// Enable or disable parallel processing
    pub fn with_parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }

    /// Enable or disable stdout status output
    pub fn with_quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Scan a directory recursively and find duplicate files
    ///
    /// # Arguments
    /// * `root` - Root directory to scan
    ///
    /// # Returns
    /// A DedupReport containing all duplicate groups and statistics
    pub fn find_duplicates(&self, root: &Path) -> Result<DedupReport, HashUtilityError> {
        let start_time = Instant::now();

        // Canonicalize root directory for consistent path handling
        let canonical_root = root.canonicalize().map_err(|e| {
            HashUtilityError::from_io_error(e, "scanning directory", Some(root.to_path_buf()))
        })?;

        if !self.quiet {
            println!("Scanning directory for duplicates: {}", root.display());
            println!("Using BLAKE3 algorithm (fast and secure)");
        }

        if self.fast_mode && !self.quiet {
            println!("Fast mode enabled: sampling first, middle, and last 100MB of large files");
        }

        // Scan directory and compute hashes
        let (hash_map, files_scanned, files_failed, total_bytes) = if self.parallel {
            self.scan_parallel(&canonical_root, start_time)?
        } else {
            self.scan_sequential(&canonical_root, start_time)?
        };

        let duration = start_time.elapsed();

        // Find duplicates by grouping files with the same hash
        let duplicate_groups = self.find_duplicate_groups(&hash_map);

        // Calculate statistics
        let duplicate_files: usize = duplicate_groups.iter().map(|g| g.count).sum();
        let wasted_space: u64 = duplicate_groups.iter().map(|g| g.wasted_space).sum();

        let stats = DedupStats {
            files_scanned,
            files_failed,
            total_bytes,
            duplicate_groups: duplicate_groups.len(),
            duplicate_files,
            wasted_space,
            duration,
        };

        Ok(DedupReport {
            stats,
            duplicate_groups,
        })
    }

    /// Sequential scan implementation
    fn scan_sequential(
        &self,
        canonical_root: &Path,
        _start_time: Instant,
    ) -> Result<(HashMap<String, Vec<(PathBuf, u64)>>, usize, usize, u64), HashUtilityError> {
        // Collect all files
        let files = self.collect_files(canonical_root)?;

        println!("Found {} files to process", files.len());

        // Track statistics
        let mut files_scanned = 0;
        let mut files_failed = 0;
        let mut total_bytes = 0u64;

        // Map from hash to list of (path, size) tuples
        let mut hash_map: HashMap<String, Vec<(PathBuf, u64)>> = HashMap::new();

        // Create progress bar
        let pb = if self.quiet {
            ProgressBar::hidden()
        } else {
            let pb = ProgressBar::new(files.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({percent}%) | Processed: {msg}")
                    .unwrap()
                    .progress_chars("=>-"),
            );
            pb
        };

        // Process each file
        for file_path in files.iter() {
            // Update progress bar
            pb.set_message(format!("{} OK, {} failed", files_scanned, files_failed));

            // Check if file still exists and is accessible
            let metadata = match fs::metadata(file_path) {
                Ok(m) => m,
                Err(_) => {
                    files_failed += 1;
                    pb.inc(1);
                    continue;
                }
            };

            let file_size = metadata.len();

            // Compute hash for the file (always use BLAKE3)
            let hash_result = if self.fast_mode {
                self.computer.compute_hash_fast(file_path, "blake3")
            } else {
                self.computer.compute_hash(file_path, "blake3")
            };

            match hash_result {
                Ok(result) => {
                    // Add to hash map
                    hash_map
                        .entry(result.hash)
                        .or_insert_with(Vec::new)
                        .push((file_path.clone(), file_size));

                    files_scanned += 1;
                    total_bytes += file_size;
                }
                Err(e) => {
                    eprintln!("Warning: Failed to hash {}: {}", file_path.display(), e);
                    files_failed += 1;
                }
            }

            pb.inc(1);
        }

        pb.finish_and_clear();

        Ok((hash_map, files_scanned, files_failed, total_bytes))
    }

    /// Parallel scan implementation using producer-consumer pattern
    fn scan_parallel(
        &self,
        canonical_root: &Path,
        _start_time: Instant,
    ) -> Result<(HashMap<String, Vec<(PathBuf, u64)>>, usize, usize, u64), HashUtilityError> {
        // Thread-safe counters
        let files_scanned = Arc::new(Mutex::new(0usize));
        let files_failed = Arc::new(Mutex::new(0usize));
        let total_bytes = Arc::new(Mutex::new(0u64));

        // Create progress bar
        let pb = if self.quiet {
            ProgressBar::hidden()
        } else {
            let pb = ProgressBar::new(0);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "[{elapsed_precise}] Counting... {pos} files found | Processing: {msg}",
                    )
                    .unwrap()
                    .progress_chars("=>-"),
            );
            pb
        };

        // Create bounded channel
        let (sender, receiver) = bounded::<PathBuf>(10000);

        // Track total files discovered
        let total_files_discovered = Arc::new(Mutex::new(0usize));
        let discovery_complete = Arc::new(Mutex::new(false));

        // Capture fast_mode for use in closure
        let fast_mode = self.fast_mode;
        let quiet = self.quiet;

        // Clone for walker thread
        let walker_root = canonical_root.to_path_buf();
        let total_files_discovered_walker = Arc::clone(&total_files_discovered);
        let discovery_complete_walker = Arc::clone(&discovery_complete);
        let pb_walker = pb.clone();

        // Spawn walker thread
        let walker_handle = thread::spawn(move || {
            let result = Self::walk_directory_streaming(
                &walker_root,
                sender,
                Arc::clone(&total_files_discovered_walker),
            );

            // Mark discovery as complete
            if !quiet {
                let total = *total_files_discovered_walker.lock().unwrap();
                pb_walker.set_length(total as u64);
                pb_walker.set_style(
                    ProgressStyle::default_bar()
                        .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({percent}%) | Processed: {msg}")
                        .unwrap()
                        .progress_chars("=>-"),
                );
            }
            *discovery_complete_walker.lock().unwrap() = true;

            result
        });

        // Clone Arc references for parallel closure
        let files_scanned_clone = Arc::clone(&files_scanned);
        let files_failed_clone = Arc::clone(&files_failed);
        let total_bytes_clone = Arc::clone(&total_bytes);
        let pb_clone = pb.clone();

        // Use rayon's par_bridge to consume from channel in parallel
        let results: Vec<_> = receiver
            .into_iter()
            .par_bridge()
            .filter_map(|file_path| {
                // Check if file still exists and is accessible
                let metadata = match fs::metadata(&file_path) {
                    Ok(m) => m,
                    Err(_) => {
                        let mut failed = files_failed_clone.lock().unwrap();
                        *failed += 1;
                        pb_clone.inc(1);
                        return None;
                    }
                };

                let file_size = metadata.len();

                // Update progress bar
                let scanned = files_scanned_clone.lock().unwrap();
                let failed = files_failed_clone.lock().unwrap();
                pb_clone.set_message(format!("{} OK, {} failed", *scanned, *failed));
                drop(scanned);
                drop(failed);

                // Compute hash (always use BLAKE3)
                let computer = HashComputer::new();
                let hash_result = if fast_mode {
                    computer.compute_hash_fast(&file_path, "blake3")
                } else {
                    computer.compute_hash(&file_path, "blake3")
                };

                let result = match hash_result {
                    Ok(result) => {
                        // Update counters
                        let mut scanned = files_scanned_clone.lock().unwrap();
                        *scanned += 1;
                        let mut bytes = total_bytes_clone.lock().unwrap();
                        *bytes += file_size;

                        Some((result.hash, file_path.clone(), file_size))
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to hash {}: {}", file_path.display(), e);
                        let mut failed = files_failed_clone.lock().unwrap();
                        *failed += 1;
                        None
                    }
                };

                pb_clone.inc(1);
                result
            })
            .collect();

        // Wait for walker thread
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

        pb.finish_and_clear();

        // Build hash map from results
        let mut hash_map: HashMap<String, Vec<(PathBuf, u64)>> = HashMap::new();
        for (hash, path, size) in results {
            hash_map
                .entry(hash)
                .or_insert_with(Vec::new)
                .push((path, size));
        }

        // Extract final statistics
        let final_scanned = *files_scanned.lock().unwrap();
        let final_failed = *files_failed.lock().unwrap();
        let final_bytes = *total_bytes.lock().unwrap();

        Ok((hash_map, final_scanned, final_failed, final_bytes))
    }

    /// Walk directory and send file paths to channel
    fn walk_directory_streaming(
        root: &Path,
        sender: crossbeam_channel::Sender<PathBuf>,
        total_files_discovered: Arc<Mutex<usize>>,
    ) -> Result<(), HashUtilityError> {
        // Load .hashignore patterns
        let ignore_handler = match IgnoreHandler::new(root) {
            Ok(handler) => Some(Arc::new(handler)),
            Err(e) => {
                eprintln!("Warning: Failed to load .hashignore: {}", e);
                None
            }
        };

        // Use jwalk for parallel directory traversal
        let mut walker = WalkDir::new(root)
            .parallelism(jwalk::Parallelism::RayonNewPool(0))
            .skip_hidden(false)
            .follow_links(false);

        if let Some(handler) = ignore_handler.clone() {
            let root = root.to_path_buf();
            walker = walker.process_read_dir(move |_depth, _dir_path, _state, children| {
                // Prune ignored directories before descending so patterns like `A/`
                // exclude their contents on the parallel walker.
                for child_result in children.iter_mut() {
                    let Ok(child) = child_result else {
                        continue;
                    };

                    if !child.file_type.is_dir() {
                        continue;
                    }

                    let child_path = child.path();
                    if let Ok(rel_path) = child_path.strip_prefix(&root) {
                        if handler.should_ignore(rel_path, true) {
                            child.read_children_path = None;
                        }
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

                    // Check if this path should be ignored
                    if let Some(ref handler) = ignore_handler {
                        if let Ok(rel_path) = path.strip_prefix(root) {
                            if handler.should_ignore(rel_path, false) {
                                continue;
                            }
                        }
                    }

                    // Send file path to channel
                    if let Err(_) = sender.send(path) {
                        break;
                    }

                    // Track total files discovered
                    let mut total = total_files_discovered.lock().unwrap();
                    *total += 1;
                }
                Err(e) => {
                    eprintln!("Warning: Error walking directory: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Recursively collect all regular files in a directory tree
    fn collect_files(&self, root: &Path) -> Result<Vec<PathBuf>, HashUtilityError> {
        let mut files = Vec::new();

        // Load .hashignore patterns
        let ignore_handler = match IgnoreHandler::new(root) {
            Ok(handler) => Some(handler),
            Err(e) => {
                eprintln!("Warning: Failed to load .hashignore: {}", e);
                None
            }
        };

        self.collect_files_recursive(root, root, &mut files, ignore_handler.as_ref())?;
        Ok(files)
    }

    /// Helper function for recursive file collection
    fn collect_files_recursive(
        &self,
        root: &Path,
        dir: &Path,
        files: &mut Vec<PathBuf>,
        ignore_handler: Option<&IgnoreHandler>,
    ) -> Result<(), HashUtilityError> {
        // Check if path exists and is accessible
        if !dir.exists() {
            return Err(HashUtilityError::DirectoryNotFound {
                path: dir.to_path_buf(),
            });
        }

        // Read directory entries
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("Warning: Cannot read directory {}: {}", dir.display(), e);
                return Ok(());
            }
        };

        // Process each entry
        for entry_result in entries {
            let entry = match entry_result {
                Ok(entry) => entry,
                Err(e) => {
                    eprintln!("Warning: Cannot read directory entry: {}", e);
                    continue;
                }
            };

            let path = entry.path();

            // Get metadata
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(e) => {
                    eprintln!(
                        "Warning: Cannot read metadata for {}: {}",
                        path.display(),
                        e
                    );
                    continue;
                }
            };

            let is_dir = metadata.is_dir();

            // Check if this path should be ignored
            if let Some(handler) = ignore_handler {
                if let Ok(rel_path) = path.strip_prefix(root) {
                    if handler.should_ignore(rel_path, is_dir) {
                        continue;
                    }
                }
            }

            if metadata.is_file() {
                files.push(path);
            } else if is_dir {
                if let Err(e) = self.collect_files_recursive(root, &path, files, ignore_handler) {
                    eprintln!(
                        "Warning: Error processing directory {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }

        Ok(())
    }

    /// Find duplicate groups from hash map
    fn find_duplicate_groups(
        &self,
        hash_map: &HashMap<String, Vec<(PathBuf, u64)>>,
    ) -> Vec<DuplicateGroupWithSize> {
        // Filter to only groups with more than one file (duplicates)
        let mut duplicates: Vec<DuplicateGroupWithSize> = hash_map
            .iter()
            .filter(|(_, paths)| paths.len() > 1)
            .map(|(hash, paths)| {
                let count = paths.len();
                let file_size = paths[0].1; // All files with same hash have same size
                let wasted_space = (count as u64 - 1) * file_size;

                let mut sorted_paths: Vec<PathBuf> = paths.iter().map(|(p, _)| p.clone()).collect();
                sorted_paths.sort();

                DuplicateGroupWithSize {
                    hash: hash.clone(),
                    paths: sorted_paths,
                    count,
                    file_size,
                    wasted_space,
                }
            })
            .collect();

        // Sort by wasted space (largest first)
        duplicates.sort_by(|a, b| b.wasted_space.cmp(&a.wasted_space));

        duplicates
    }
}

impl Default for DedupEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_walk_directory_streaming_skips_ignored_directory_patterns() {
        let test_dir = "test_dedup_ignore_directory_pattern";
        fs::create_dir_all(format!("{}/A/sub", test_dir)).unwrap();
        fs::create_dir_all(format!("{}/B", test_dir)).unwrap();

        fs::write(format!("{}/.hashignore", test_dir), b"A/\n").unwrap();
        fs::write(format!("{}/A/file1.txt", test_dir), b"one").unwrap();
        fs::write(format!("{}/A/sub/file2.txt", test_dir), b"two").unwrap();
        fs::write(format!("{}/B/file3.txt", test_dir), b"three").unwrap();

        let (sender, receiver) = bounded::<PathBuf>(16);
        let total_files_discovered = Arc::new(Mutex::new(0usize));

        DedupEngine::walk_directory_streaming(
            Path::new(test_dir),
            sender,
            Arc::clone(&total_files_discovered),
        )
        .unwrap();

        let files: Vec<PathBuf> = receiver.iter().collect();

        assert_eq!(files.len(), 1);
        assert_eq!(*total_files_discovered.lock().unwrap(), 1);
        assert!(files.iter().any(|path| path.ends_with(Path::new("B").join("file3.txt"))));
        assert!(!files
            .iter()
            .any(|path| path.ends_with(Path::new("A").join("file1.txt"))));
        assert!(!files.iter().any(|path| {
            path.ends_with(Path::new("A").join("sub").join("file2.txt"))
        }));

        fs::remove_dir_all(test_dir).unwrap();
    }
}
