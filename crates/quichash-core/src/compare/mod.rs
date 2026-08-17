//! Manifest comparison.
// Compares two hash databases and generates detailed comparison reports

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::database::{DatabaseEntry, DatabaseFormat, DatabaseHandler};
use crate::error::HashUtilityError;

mod report;

/// Metadata about a database file
#[derive(Debug, Clone, serde::Serialize)]
pub struct DatabaseInfo {
    /// Database path.
    pub path: PathBuf,
    /// Detected format name.
    pub format: String,
    /// Database file size.
    pub size_bytes: u64,
    /// Number of parsed file entries.
    pub file_count: usize,
    /// Last-modified timestamp when available.
    pub modified: Option<String>,
}

/// Result of comparing a single file between two databases
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChangedFile {
    /// Path present in both databases.
    pub path: PathBuf,
    /// Digest recorded in the first database.
    pub hash_db1: String,
    /// Digest recorded in the second database.
    pub hash_db2: String,
}

/// A file that was moved/renamed between databases
#[derive(Debug, Clone, serde::Serialize)]
pub struct MovedFile {
    /// Path in the first database.
    pub from_path: PathBuf,
    /// Path in the second database.
    pub to_path: PathBuf,
    /// Digest shared by both paths.
    pub hash: String,
}

/// Group of files with the same hash (duplicates)
#[derive(Debug, Clone, serde::Serialize)]
pub struct DuplicateGroup {
    /// Digest shared by every path in the group.
    pub hash: String,
    /// Paths with the shared digest.
    pub paths: Vec<PathBuf>,
    /// Number of paths in the group.
    pub count: usize,
}

/// Comprehensive comparison report between two databases
#[derive(Debug, Clone, serde::Serialize)]
pub struct CompareReport {
    /// Metadata for the first database.
    pub db1_info: DatabaseInfo,
    /// Metadata for the second database.
    pub db2_info: DatabaseInfo,
    /// Total entries in the first database.
    pub db1_total_files: usize,
    /// Total entries in the second database.
    pub db2_total_files: usize,
    /// Paths with equal digest values in both databases.
    pub unchanged_files: usize,
    /// Same paths whose digest values differ.
    pub changed_files: Vec<ChangedFile>,
    /// Equal digests associated with different paths.
    pub moved_files: Vec<MovedFile>,
    /// Paths found only in the first database.
    pub removed_files: Vec<PathBuf>,
    /// Paths found only in the second database.
    pub added_files: Vec<PathBuf>,
    /// Duplicate digest groups in the first database.
    pub duplicates_db1: Vec<DuplicateGroup>,
    /// Duplicate digest groups in the second database.
    pub duplicates_db2: Vec<DuplicateGroup>,
}

/// Engine for comparing two hash databases
pub struct CompareEngine;

impl CompareEngine {
    /// Create a new CompareEngine
    pub fn new() -> Self {
        CompareEngine
    }

    /// Compare two hash databases and generate a detailed report
    ///
    /// # Arguments
    /// * `database1` - Path to the first database file
    /// * `database2` - Path to the second database file
    ///
    /// # Returns
    /// A CompareReport containing all comparison findings
    ///
    /// # Errors
    /// Returns an error if either database cannot be read
    pub fn compare(
        &self,
        database1: &Path,
        database2: &Path,
    ) -> Result<CompareReport, HashUtilityError> {
        if DatabaseHandler::verification_checksum_algorithm(database1)?.is_some()
            || DatabaseHandler::verification_checksum_algorithm(database2)?.is_some()
        {
            return Err(HashUtilityError::InvalidArguments {
                message: "two-column checksum files are supported only by verification".to_owned(),
            });
        }
        // Gather database metadata
        let db1_info = Self::get_database_info(database1)?;
        let db2_info = Self::get_database_info(database2)?;

        // Load both databases
        let db1 = DatabaseHandler::read_database(database1)?;
        let db2 = DatabaseHandler::read_database(database2)?;

        // Detect duplicates in each database
        let duplicates_db1 = Self::find_duplicates(&db1);
        let duplicates_db2 = Self::find_duplicates(&db2);

        // Get all unique file paths from both databases
        let all_paths: HashSet<PathBuf> = db1.keys().chain(db2.keys()).cloned().collect();

        // Classify files
        let mut unchanged_count = 0;
        let mut changed_files = Vec::new();
        let mut removed_files = Vec::new();
        let mut added_files = Vec::new();

        for path in all_paths {
            match (db1.get(&path), db2.get(&path)) {
                (Some(entry1), Some(entry2)) => {
                    // File exists in both databases
                    if entry1.hash == entry2.hash {
                        // Hashes match - unchanged
                        unchanged_count += 1;
                    } else {
                        // Hashes differ - changed
                        changed_files.push(ChangedFile {
                            path: path.clone(),
                            hash_db1: entry1.hash.clone(),
                            hash_db2: entry2.hash.clone(),
                        });
                    }
                }
                (Some(_), None) => {
                    // File exists in DB1 but not DB2 - potentially removed or moved
                    removed_files.push(path.clone());
                }
                (None, Some(_)) => {
                    // File exists in DB2 but not DB1 - potentially added or moved
                    added_files.push(path.clone());
                }
                (None, None) => {
                    // This should never happen since we got the path from one of the databases
                    unreachable!("Path should exist in at least one database");
                }
            }
        }

        // Detect moved files: files with same hash but different paths
        // Build hash-to-path map for removed files (from DB1)
        let mut removed_by_hash: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for path in &removed_files {
            if let Some(entry) = db1.get(path) {
                removed_by_hash
                    .entry(entry.hash.clone())
                    .or_default()
                    .push(path.clone());
            }
        }

        // Build hash-to-path map for added files (from DB2)
        let mut added_by_hash: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for path in &added_files {
            if let Some(entry) = db2.get(path) {
                added_by_hash
                    .entry(entry.hash.clone())
                    .or_default()
                    .push(path.clone());
            }
        }

        // Find moves: same hash in both removed and added
        let mut moved_files = Vec::new();
        let mut moved_from_paths: HashSet<PathBuf> = HashSet::new();
        let mut moved_to_paths: HashSet<PathBuf> = HashSet::new();

        for (hash, from_paths) in &removed_by_hash {
            if let Some(to_paths) = added_by_hash.get(hash) {
                // Match up files with same hash - pair them 1:1
                for (from_path, to_path) in from_paths.iter().zip(to_paths.iter()) {
                    moved_files.push(MovedFile {
                        from_path: from_path.clone(),
                        to_path: to_path.clone(),
                        hash: hash.clone(),
                    });
                    moved_from_paths.insert(from_path.clone());
                    moved_to_paths.insert(to_path.clone());
                }
            }
        }

        // Remove moved files from removed and added lists
        removed_files.retain(|p| !moved_from_paths.contains(p));
        added_files.retain(|p| !moved_to_paths.contains(p));

        // Sort results for consistent output
        changed_files.sort_by(|a, b| a.path.cmp(&b.path));
        moved_files.sort_by(|a, b| a.from_path.cmp(&b.from_path));
        removed_files.sort();
        added_files.sort();

        // Update file counts in database info
        let db1_info = DatabaseInfo {
            file_count: db1.len(),
            ..db1_info
        };
        let db2_info = DatabaseInfo {
            file_count: db2.len(),
            ..db2_info
        };

        Ok(CompareReport {
            db1_info,
            db2_info,
            db1_total_files: db1.len(),
            db2_total_files: db2.len(),
            unchanged_files: unchanged_count,
            changed_files,
            moved_files,
            removed_files,
            added_files,
            duplicates_db1,
            duplicates_db2,
        })
    }

    /// Get metadata about a database file
    fn get_database_info(path: &Path) -> Result<DatabaseInfo, HashUtilityError> {
        use std::fs;

        // Get file metadata
        let metadata = fs::metadata(path).map_err(|e| {
            HashUtilityError::from_io_error(
                e,
                "reading database metadata",
                Some(path.to_path_buf()),
            )
        })?;

        // Detect format
        let format = DatabaseHandler::detect_format(path)?;
        let format_str = match format {
            DatabaseFormat::Quichash => "quichash",
            DatabaseFormat::Hashdeep => "hashdeep",
        };

        // Get modification time
        #[cfg(feature = "reporting")]
        let modified = metadata.modified().ok().map(|time| {
            let datetime: chrono::DateTime<chrono::Utc> = time.into();
            datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        });
        #[cfg(not(feature = "reporting"))]
        let modified = metadata.modified().ok().map(|time| format!("{time:?}"));

        Ok(DatabaseInfo {
            path: path.to_path_buf(),
            format: format_str.to_string(),
            size_bytes: metadata.len(),
            file_count: 0, // Will be updated after reading
            modified,
        })
    }

    /// Find duplicate hashes within a database
    /// Find duplicate files within a single database
    ///
    /// # Arguments
    /// * `database` - The database to search for duplicates
    ///
    /// # Returns
    /// A vector of DuplicateGroup, each containing files with the same hash
    pub fn find_duplicates(database: &HashMap<PathBuf, DatabaseEntry>) -> Vec<DuplicateGroup> {
        // Build a map from hash to list of paths
        let mut hash_to_paths: HashMap<String, Vec<PathBuf>> = HashMap::new();

        for (path, entry) in database {
            hash_to_paths
                .entry(entry.hash.clone())
                .or_default()
                .push(path.clone());
        }

        // Filter to only groups with more than one file (duplicates)
        let mut duplicates: Vec<DuplicateGroup> = hash_to_paths
            .into_iter()
            .filter(|(_, paths)| paths.len() > 1)
            .map(|(hash, mut paths)| {
                paths.sort();
                let count = paths.len();
                DuplicateGroup { hash, paths, count }
            })
            .collect();

        // Sort by hash for consistent output
        duplicates.sort_by(|a, b| a.hash.cmp(&b.hash));

        duplicates
    }
}

impl Default for CompareEngine {
    fn default() -> Self {
        Self::new()
    }
}
