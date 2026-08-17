//! Manifest analysis.
// Analyzes a single hash database and generates statistics

use std::collections::HashSet;
use std::path::Path;

use crate::database::{DatabaseFormat, DatabaseHandler};
use crate::error::HashUtilityError;

mod helpers;
mod report;
#[cfg(test)]
mod tests;

pub use report::{format_size, AnalyzeReport, AnalyzeStats, DuplicateGroup, EntryWithSize};

/// Engine for analyzing hash databases
pub struct AnalyzeEngine;

impl AnalyzeEngine {
    /// Create a new AnalyzeEngine
    pub fn new() -> Self {
        AnalyzeEngine
    }

    /// Analyze a database file and generate a report
    pub fn analyze(&self, database_path: &Path) -> Result<AnalyzeReport, HashUtilityError> {
        if DatabaseHandler::verification_checksum_algorithm(database_path)?.is_some() {
            return Err(HashUtilityError::InvalidArguments {
                message: "two-column checksum files are supported only by verification".to_owned(),
            });
        }
        // Get database file size
        let database_file_size = std::fs::metadata(database_path)
            .map_err(|e| {
                HashUtilityError::from_io_error(
                    e,
                    "reading database metadata",
                    Some(database_path.to_path_buf()),
                )
            })?
            .len();

        // Detect format
        let format = DatabaseHandler::detect_format(database_path)?;
        let format_str = match format {
            DatabaseFormat::Quichash => "quichash",
            DatabaseFormat::Hashdeep => "hashdeep",
        };

        // Read database with size information
        let entries = helpers::read_database_with_sizes(database_path, format)?;

        // Collect statistics
        let total_files = entries.len();
        let mut algorithms: HashSet<String> = HashSet::new();
        let mut fast_mode_files = 0;
        let mut normal_mode_files = 0;
        let mut total_file_size: Option<u64> = None;
        let mut has_sizes = false;

        for entry in entries.values() {
            algorithms.insert(entry.algorithm.clone());
            if entry.fast_mode {
                fast_mode_files += 1;
            } else {
                normal_mode_files += 1;
            }
            if let Some(size) = entry.file_size {
                has_sizes = true;
                *total_file_size.get_or_insert(0) += size;
            }
        }

        // Find duplicates
        let duplicate_groups = helpers::find_duplicates(&entries);
        let duplicate_group_count = duplicate_groups.len();
        let duplicate_files: usize = duplicate_groups.iter().map(|g| g.count).sum();
        let unique_hashes = total_files - duplicate_files + duplicate_group_count;

        // Calculate potential savings
        let potential_savings: Option<u64> = if has_sizes {
            Some(duplicate_groups.iter().filter_map(|g| g.wasted_space).sum())
        } else {
            None
        };

        let mut algo_list: Vec<String> = algorithms.into_iter().collect();
        algo_list.sort();

        Ok(AnalyzeReport {
            database_path: database_path.to_path_buf(),
            stats: AnalyzeStats {
                total_files,
                unique_hashes,
                duplicate_groups: duplicate_group_count,
                duplicate_files,
                database_file_size,
                database_format: format_str.to_string(),
                algorithms: algo_list,
                fast_mode_files,
                normal_mode_files,
                total_file_size: if has_sizes { total_file_size } else { None },
                potential_savings,
            },
            duplicate_groups,
        })
    }
}

impl Default for AnalyzeEngine {
    fn default() -> Self {
        Self::new()
    }
}
