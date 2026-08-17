//! Duplicate-file analysis.
// Finds duplicate files within a directory by comparing hash values

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::error::HashUtilityError;
use crate::hash::HashComputer;

mod report;
mod scanner;
#[cfg(test)]
mod tests;

pub use report::{DedupReport, DedupStats, DuplicateGroupWithSize};

/// Engine for finding duplicate files in a directory
pub struct DedupEngine {
    computer: HashComputer,
    fast_mode: bool,
    parallel: bool,
}

impl DedupEngine {
    /// Create a new DedupEngine with default settings
    /// Always uses BLAKE3 algorithm (fast and secure)
    pub fn new() -> Self {
        Self {
            computer: HashComputer::new(),
            fast_mode: false,
            parallel: true, // Default to parallel for better performance
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

        println!("Scanning directory for duplicates: {}", root.display());
        println!("Using BLAKE3 algorithm (fast and secure)");

        if self.fast_mode {
            println!("Fast mode enabled: sampling first, middle, and last 100MB of large files");
        }

        // Scan directory and compute hashes
        let (hash_map, files_scanned, files_failed, total_bytes) = if self.parallel {
            scanner::scan_parallel(self.fast_mode, &canonical_root, start_time)?
        } else {
            scanner::scan_sequential(&self.computer, self.fast_mode, &canonical_root, start_time)?
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
        duplicates.sort_by_key(|b| std::cmp::Reverse(b.wasted_space));

        duplicates
    }
}

impl Default for DedupEngine {
    fn default() -> Self {
        Self::new()
    }
}
