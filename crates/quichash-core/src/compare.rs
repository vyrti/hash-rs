//! Manifest comparison.
// Compares two hash databases and generates detailed comparison reports

use crate::database::{DatabaseEntry, DatabaseFormat, DatabaseHandler};
use crate::error::HashUtilityError;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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

/// Format bytes as human-readable size
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

impl CompareReport {
    /// Legacy display hook retained for API compatibility.
    ///
    /// The reusable core does not write to the terminal. Use
    /// [`Self::to_plain_text`] and render the returned string in the embedding
    /// application.
    pub fn display(&self) {
        println!("\n=== Database Comparison Report ===\n");

        // Summary section
        println!("Summary:");
        println!("  Database 1: {} files", self.db1_total_files);
        println!("  Database 2: {} files", self.db2_total_files);
        println!("  Unchanged:  {} files", self.unchanged_files);
        println!("  Changed:    {} files", self.changed_files.len());
        println!("  Moved:      {} files", self.moved_files.len());
        println!("  Removed:    {} files", self.removed_files.len());
        println!("  Added:      {} files", self.added_files.len());
        println!("  Duplicates in DB1: {} groups", self.duplicates_db1.len());
        println!("  Duplicates in DB2: {} groups", self.duplicates_db2.len());

        // Changed files section
        if !self.changed_files.is_empty() {
            println!("\nChanged Files:");
            for changed in &self.changed_files {
                println!("  {}", changed.path.display());
                println!("    DB1: {}", changed.hash_db1);
                println!("    DB2: {}", changed.hash_db2);
            }
        }

        // Moved files section
        if !self.moved_files.is_empty() {
            println!("\nMoved Files:");
            for moved in &self.moved_files {
                println!(
                    "  {} -> {}",
                    moved.from_path.display(),
                    moved.to_path.display()
                );
            }
        }

        // Removed files section
        if !self.removed_files.is_empty() {
            println!("\nRemoved Files (in DB1 but not DB2):");
            for path in &self.removed_files {
                println!("  {}", path.display());
            }
        }

        // Added files section
        if !self.added_files.is_empty() {
            println!("\nAdded Files (in DB2 but not DB1):");
            for path in &self.added_files {
                println!("  {}", path.display());
            }
        }

        // Duplicates in DB1
        if !self.duplicates_db1.is_empty() {
            println!("\nDuplicates in Database 1:");
            for group in &self.duplicates_db1 {
                println!("  Hash: {} ({} files)", group.hash, group.count);
                for path in &group.paths {
                    println!("    {}", path.display());
                }
            }
        }

        // Duplicates in DB2
        if !self.duplicates_db2.is_empty() {
            println!("\nDuplicates in Database 2:");
            for group in &self.duplicates_db2 {
                println!("  Hash: {} ({} files)", group.hash, group.count);
                for path in &group.paths {
                    println!("    {}", path.display());
                }
            }
        }

        println!();
    }

    /// Format the comparison report as plain text string
    pub fn to_plain_text(&self) -> String {
        let mut output = String::new();

        output.push_str("\n=== Database Comparison Report ===\n\n");

        // Database info section
        output.push_str("Databases:\n");
        output.push_str(&format!("  DB1: {}\n", self.db1_info.path.display()));
        output.push_str(&format!(
            "       Format: {}, Size: {}, Files: {}\n",
            self.db1_info.format,
            format_size(self.db1_info.size_bytes),
            self.db1_info.file_count
        ));
        if let Some(ref modified) = self.db1_info.modified {
            output.push_str(&format!("       Modified: {}\n", modified));
        }
        output.push_str(&format!("  DB2: {}\n", self.db2_info.path.display()));
        output.push_str(&format!(
            "       Format: {}, Size: {}, Files: {}\n",
            self.db2_info.format,
            format_size(self.db2_info.size_bytes),
            self.db2_info.file_count
        ));
        if let Some(ref modified) = self.db2_info.modified {
            output.push_str(&format!("       Modified: {}\n", modified));
        }
        output.push('\n');

        // Summary section
        output.push_str("Summary:\n");
        output.push_str(&format!("  Unchanged:  {} files\n", self.unchanged_files));
        output.push_str(&format!(
            "  Changed:    {} files\n",
            self.changed_files.len()
        ));
        output.push_str(&format!("  Moved:      {} files\n", self.moved_files.len()));
        output.push_str(&format!(
            "  Removed:    {} files\n",
            self.removed_files.len()
        ));
        output.push_str(&format!("  Added:      {} files\n", self.added_files.len()));

        // Changed files section
        if !self.changed_files.is_empty() {
            output.push_str("\nChanged Files:\n");
            for changed in &self.changed_files {
                output.push_str(&format!("  {}\n", changed.path.display()));
                output.push_str(&format!("    DB1: {}\n", changed.hash_db1));
                output.push_str(&format!("    DB2: {}\n", changed.hash_db2));
            }
        }

        // Moved files section
        if !self.moved_files.is_empty() {
            output.push_str("\nMoved Files:\n");
            for moved in &self.moved_files {
                output.push_str(&format!(
                    "  {} -> {}\n",
                    moved.from_path.display(),
                    moved.to_path.display()
                ));
            }
        }

        // Removed files section
        if !self.removed_files.is_empty() {
            output.push_str("\nRemoved Files (in DB1 but not DB2):\n");
            for path in &self.removed_files {
                output.push_str(&format!("  {}\n", path.display()));
            }
        }

        // Added files section
        if !self.added_files.is_empty() {
            output.push_str("\nAdded Files (in DB2 but not DB1):\n");
            for path in &self.added_files {
                output.push_str(&format!("  {}\n", path.display()));
            }
        }

        output.push('\n');
        output
    }

    /// Format the comparison report in hashdeep audit style
    ///
    /// This format matches hashdeep's audit mode (-a -vvv) output style:
    /// - Summary header with pass/fail status
    /// - Category counts
    /// - Detailed file listings with -vvv style
    pub fn to_hashdeep(&self) -> String {
        let mut output = String::new();

        // Audit result header (like hashdeep)
        let audit_passed = self.changed_files.is_empty()
            && self.moved_files.is_empty()
            && self.removed_files.is_empty()
            && self.added_files.is_empty();

        if audit_passed {
            output.push_str("hashdeep: Audit passed\n");
        } else {
            output.push_str("hashdeep: Audit failed\n");
        }

        // Summary counts (like hashdeep -vv)
        output.push_str(&format!(
            "          Files matched: {}\n",
            self.unchanged_files
        ));
        output.push_str(&format!(
            "         Files modified: {}\n",
            self.changed_files.len()
        ));
        output.push_str(&format!(
            "            Files moved: {}\n",
            self.moved_files.len()
        ));
        output.push_str(&format!(
            "        New files found: {}\n",
            self.added_files.len()
        ));
        output.push_str(&format!(
            "  Known files not found: {}\n",
            self.removed_files.len()
        ));

        // Detailed listings (like hashdeep -vvv)
        if !self.changed_files.is_empty() {
            output.push_str("\nModified files:\n");
            for changed in &self.changed_files {
                output.push_str(&format!(
                    "  {}\n    Known hash:    {}\n    Computed hash: {}\n",
                    changed.path.display(),
                    changed.hash_db1,
                    changed.hash_db2
                ));
            }
        }

        // Moved files - hashdeep style "Moved from X"
        if !self.moved_files.is_empty() {
            output.push_str("\nMoved files:\n");
            for moved in &self.moved_files {
                output.push_str(&format!(
                    "  {}: Moved from {}\n",
                    moved.to_path.display(),
                    moved.from_path.display()
                ));
            }
        }

        if !self.added_files.is_empty() {
            output.push_str("\nNew files:\n");
            for path in &self.added_files {
                output.push_str(&format!("  {}\n", path.display()));
            }
        }

        if !self.removed_files.is_empty() {
            output.push_str("\nKnown files not found:\n");
            for path in &self.removed_files {
                output.push_str(&format!("  {}\n", path.display()));
            }
        }

        output
    }

    /// Format the comparison report as JSON string
    #[cfg(feature = "reporting")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        #[derive(serde::Serialize)]
        struct JsonOutput {
            metadata: Metadata,
            databases: Databases,
            summary: Summary,
            unchanged_files: usize,
            changed_files: Vec<ChangedFileJson>,
            moved_files: Vec<MovedFileJson>,
            removed_files: Vec<String>,
            added_files: Vec<String>,
        }

        #[derive(serde::Serialize)]
        struct Metadata {
            timestamp: String,
        }

        #[derive(serde::Serialize)]
        struct Databases {
            db1: DatabaseInfoJson,
            db2: DatabaseInfoJson,
        }

        #[derive(serde::Serialize)]
        struct DatabaseInfoJson {
            path: String,
            format: String,
            size_bytes: u64,
            file_count: usize,
            modified: Option<String>,
        }

        #[derive(serde::Serialize)]
        struct Summary {
            unchanged_count: usize,
            changed_count: usize,
            moved_count: usize,
            removed_count: usize,
            added_count: usize,
        }

        #[derive(serde::Serialize)]
        struct ChangedFileJson {
            path: String,
            hash_db1: String,
            hash_db2: String,
        }

        #[derive(serde::Serialize)]
        struct MovedFileJson {
            from_path: String,
            to_path: String,
            hash: String,
        }

        let output = JsonOutput {
            metadata: Metadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
            databases: Databases {
                db1: DatabaseInfoJson {
                    path: self.db1_info.path.display().to_string(),
                    format: self.db1_info.format.clone(),
                    size_bytes: self.db1_info.size_bytes,
                    file_count: self.db1_info.file_count,
                    modified: self.db1_info.modified.clone(),
                },
                db2: DatabaseInfoJson {
                    path: self.db2_info.path.display().to_string(),
                    format: self.db2_info.format.clone(),
                    size_bytes: self.db2_info.size_bytes,
                    file_count: self.db2_info.file_count,
                    modified: self.db2_info.modified.clone(),
                },
            },
            summary: Summary {
                unchanged_count: self.unchanged_files,
                changed_count: self.changed_files.len(),
                moved_count: self.moved_files.len(),
                removed_count: self.removed_files.len(),
                added_count: self.added_files.len(),
            },
            unchanged_files: self.unchanged_files,
            changed_files: self
                .changed_files
                .iter()
                .map(|cf| ChangedFileJson {
                    path: cf.path.display().to_string(),
                    hash_db1: cf.hash_db1.clone(),
                    hash_db2: cf.hash_db2.clone(),
                })
                .collect(),
            moved_files: self
                .moved_files
                .iter()
                .map(|mf| MovedFileJson {
                    from_path: mf.from_path.display().to_string(),
                    to_path: mf.to_path.display().to_string(),
                    hash: mf.hash.clone(),
                })
                .collect(),
            removed_files: self
                .removed_files
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            added_files: self
                .added_files
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
        };

        serde_json::to_string_pretty(&output)
    }
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
            DatabaseFormat::Standard => "standard",
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
    ///
    /// # Arguments
    /// * `database` - The database to search for duplicates
    ///
    /// # Returns
    /// A vector of DuplicateGroup, each containing files with the same hash
    fn find_duplicates(database: &HashMap<PathBuf, DatabaseEntry>) -> Vec<DuplicateGroup> {
        // Build a map from hash to list of paths
        let mut hash_to_paths: HashMap<String, Vec<PathBuf>> = HashMap::new();

        for (path, entry) in database {
            hash_to_paths
                .entry(entry.hash.clone())
                .or_insert_with(Vec::new)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DatabaseHandler;
    use std::fs;

    #[test]
    fn test_compare_identical_databases() {
        // Create two identical databases
        let db1_path = "test_compare_identical_db1.txt";
        let db2_path = "test_compare_identical_db2.txt";

        let content = "hash1  sha256  normal  file1.txt\n\
                       hash2  sha256  normal  file2.txt\n\
                       hash3  sha256  normal  file3.txt\n";

        fs::write(db1_path, content).unwrap();
        fs::write(db2_path, content).unwrap();

        let engine = CompareEngine::new();
        let report = engine
            .compare(Path::new(db1_path), Path::new(db2_path))
            .unwrap();

        assert_eq!(report.db1_total_files, 3);
        assert_eq!(report.db2_total_files, 3);
        assert_eq!(report.unchanged_files, 3);
        assert_eq!(report.changed_files.len(), 0);
        assert_eq!(report.removed_files.len(), 0);
        assert_eq!(report.added_files.len(), 0);
        assert_eq!(report.duplicates_db1.len(), 0);
        assert_eq!(report.duplicates_db2.len(), 0);

        fs::remove_file(db1_path).unwrap();
        fs::remove_file(db2_path).unwrap();
    }

    #[test]
    fn test_compare_with_changed_files() {
        let db1_path = "test_compare_changed_db1.txt";
        let db2_path = "test_compare_changed_db2.txt";

        let content1 = "hash1  sha256  normal  file1.txt\n\
                        hash2  sha256  normal  file2.txt\n\
                        hash3  sha256  normal  file3.txt\n";

        let content2 = "hash1  sha256  normal  file1.txt\n\
                        hash2_modified  sha256  normal  file2.txt\n\
                        hash3  sha256  normal  file3.txt\n";

        fs::write(db1_path, content1).unwrap();
        fs::write(db2_path, content2).unwrap();

        let engine = CompareEngine::new();
        let report = engine
            .compare(Path::new(db1_path), Path::new(db2_path))
            .unwrap();

        assert_eq!(report.db1_total_files, 3);
        assert_eq!(report.db2_total_files, 3);
        assert_eq!(report.unchanged_files, 2);
        assert_eq!(report.changed_files.len(), 1);
        assert_eq!(report.removed_files.len(), 0);
        assert_eq!(report.added_files.len(), 0);

        let changed = &report.changed_files[0];
        assert_eq!(changed.path, PathBuf::from("file2.txt"));
        assert_eq!(changed.hash_db1, "hash2");
        assert_eq!(changed.hash_db2, "hash2_modified");

        fs::remove_file(db1_path).unwrap();
        fs::remove_file(db2_path).unwrap();
    }

    #[test]
    fn test_compare_with_removed_files() {
        let db1_path = "test_compare_removed_db1.txt";
        let db2_path = "test_compare_removed_db2.txt";

        let content1 = "hash1  sha256  normal  file1.txt\n\
                        hash2  sha256  normal  file2.txt\n\
                        hash3  sha256  normal  file3.txt\n";

        let content2 = "hash1  sha256  normal  file1.txt\n\
                        hash3  sha256  normal  file3.txt\n";

        fs::write(db1_path, content1).unwrap();
        fs::write(db2_path, content2).unwrap();

        let engine = CompareEngine::new();
        let report = engine
            .compare(Path::new(db1_path), Path::new(db2_path))
            .unwrap();

        assert_eq!(report.db1_total_files, 3);
        assert_eq!(report.db2_total_files, 2);
        assert_eq!(report.unchanged_files, 2);
        assert_eq!(report.changed_files.len(), 0);
        assert_eq!(report.removed_files.len(), 1);
        assert_eq!(report.added_files.len(), 0);

        assert_eq!(report.removed_files[0], PathBuf::from("file2.txt"));

        fs::remove_file(db1_path).unwrap();
        fs::remove_file(db2_path).unwrap();
    }

    #[test]
    fn test_compare_with_added_files() {
        let db1_path = "test_compare_added_db1.txt";
        let db2_path = "test_compare_added_db2.txt";

        let content1 = "hash1  sha256  normal  file1.txt\n\
                        hash2  sha256  normal  file2.txt\n";

        let content2 = "hash1  sha256  normal  file1.txt\n\
                        hash2  sha256  normal  file2.txt\n\
                        hash3  sha256  normal  file3.txt\n";

        fs::write(db1_path, content1).unwrap();
        fs::write(db2_path, content2).unwrap();

        let engine = CompareEngine::new();
        let report = engine
            .compare(Path::new(db1_path), Path::new(db2_path))
            .unwrap();

        assert_eq!(report.db1_total_files, 2);
        assert_eq!(report.db2_total_files, 3);
        assert_eq!(report.unchanged_files, 2);
        assert_eq!(report.changed_files.len(), 0);
        assert_eq!(report.removed_files.len(), 0);
        assert_eq!(report.added_files.len(), 1);

        assert_eq!(report.added_files[0], PathBuf::from("file3.txt"));

        fs::remove_file(db1_path).unwrap();
        fs::remove_file(db2_path).unwrap();
    }

    #[test]
    fn test_compare_with_duplicates() {
        let db1_path = "test_compare_duplicates_db1.txt";
        let db2_path = "test_compare_duplicates_db2.txt";

        // DB1 has duplicates: file1 and file2 have the same hash
        let content1 = "hash_duplicate  sha256  normal  file1.txt\n\
                        hash_duplicate  sha256  normal  file2.txt\n\
                        hash3  sha256  normal  file3.txt\n";

        // DB2 has different duplicates: file3 and file4 have the same hash
        let content2 = "hash1  sha256  normal  file1.txt\n\
                        hash2  sha256  normal  file2.txt\n\
                        hash_dup2  sha256  normal  file3.txt\n\
                        hash_dup2  sha256  normal  file4.txt\n";

        fs::write(db1_path, content1).unwrap();
        fs::write(db2_path, content2).unwrap();

        let engine = CompareEngine::new();
        let report = engine
            .compare(Path::new(db1_path), Path::new(db2_path))
            .unwrap();

        assert_eq!(report.db1_total_files, 3);
        assert_eq!(report.db2_total_files, 4);
        assert_eq!(report.duplicates_db1.len(), 1);
        assert_eq!(report.duplicates_db2.len(), 1);

        // Check DB1 duplicates
        let dup1 = &report.duplicates_db1[0];
        assert_eq!(dup1.hash, "hash_duplicate");
        assert_eq!(dup1.count, 2);
        assert_eq!(dup1.paths.len(), 2);

        // Check DB2 duplicates
        let dup2 = &report.duplicates_db2[0];
        assert_eq!(dup2.hash, "hash_dup2");
        assert_eq!(dup2.count, 2);
        assert_eq!(dup2.paths.len(), 2);

        fs::remove_file(db1_path).unwrap();
        fs::remove_file(db2_path).unwrap();
    }

    #[test]
    fn test_compare_complex_scenario() {
        let db1_path = "test_compare_complex_db1.txt";
        let db2_path = "test_compare_complex_db2.txt";

        // Complex scenario with unchanged, changed, removed, added, and duplicates
        let content1 = "hash_unchanged  sha256  normal  unchanged.txt\n\
                        hash_old  sha256  normal  changed.txt\n\
                        hash_removed  sha256  normal  removed.txt\n\
                        hash_dup  sha256  normal  dup1.txt\n\
                        hash_dup  sha256  normal  dup2.txt\n";

        let content2 = "hash_unchanged  sha256  normal  unchanged.txt\n\
                        hash_new  sha256  normal  changed.txt\n\
                        hash_added  sha256  normal  added.txt\n\
                        hash_dup2  sha256  normal  dup3.txt\n\
                        hash_dup2  sha256  normal  dup4.txt\n\
                        hash_dup2  sha256  normal  dup5.txt\n";

        fs::write(db1_path, content1).unwrap();
        fs::write(db2_path, content2).unwrap();

        let engine = CompareEngine::new();
        let report = engine
            .compare(Path::new(db1_path), Path::new(db2_path))
            .unwrap();

        assert_eq!(report.db1_total_files, 5);
        assert_eq!(report.db2_total_files, 6);
        assert_eq!(report.unchanged_files, 1);
        assert_eq!(report.changed_files.len(), 1);
        assert_eq!(report.removed_files.len(), 3); // removed.txt, dup1.txt, dup2.txt
        assert_eq!(report.added_files.len(), 4); // added.txt, dup3.txt, dup4.txt, dup5.txt
        assert_eq!(report.duplicates_db1.len(), 1);
        assert_eq!(report.duplicates_db2.len(), 1);

        // Check changed file
        let changed = &report.changed_files[0];
        assert_eq!(changed.path, PathBuf::from("changed.txt"));
        assert_eq!(changed.hash_db1, "hash_old");
        assert_eq!(changed.hash_db2, "hash_new");

        // Check duplicates
        assert_eq!(report.duplicates_db1[0].count, 2);
        assert_eq!(report.duplicates_db2[0].count, 3);

        fs::remove_file(db1_path).unwrap();
        fs::remove_file(db2_path).unwrap();
    }

    #[test]
    fn test_find_duplicates_no_duplicates() {
        let mut db = HashMap::new();
        db.insert(
            PathBuf::from("file1.txt"),
            DatabaseEntry {
                hash: "hash1".to_string(),
                algorithm: "sha256".to_string(),
                fast_mode: false,
            },
        );
        db.insert(
            PathBuf::from("file2.txt"),
            DatabaseEntry {
                hash: "hash2".to_string(),
                algorithm: "sha256".to_string(),
                fast_mode: false,
            },
        );

        let duplicates = CompareEngine::find_duplicates(&db);
        assert_eq!(duplicates.len(), 0);
    }

    #[test]
    fn test_find_duplicates_with_duplicates() {
        let mut db = HashMap::new();
        db.insert(
            PathBuf::from("file1.txt"),
            DatabaseEntry {
                hash: "hash_dup".to_string(),
                algorithm: "sha256".to_string(),
                fast_mode: false,
            },
        );
        db.insert(
            PathBuf::from("file2.txt"),
            DatabaseEntry {
                hash: "hash_dup".to_string(),
                algorithm: "sha256".to_string(),
                fast_mode: false,
            },
        );
        db.insert(
            PathBuf::from("file3.txt"),
            DatabaseEntry {
                hash: "hash_unique".to_string(),
                algorithm: "sha256".to_string(),
                fast_mode: false,
            },
        );

        let duplicates = CompareEngine::find_duplicates(&db);
        assert_eq!(duplicates.len(), 1);

        let dup_group = &duplicates[0];
        assert_eq!(dup_group.hash, "hash_dup");
        assert_eq!(dup_group.count, 2);
        assert_eq!(dup_group.paths.len(), 2);
    }

    #[test]
    fn test_compare_compressed_databases() {
        // Create two plain text databases
        let db1_plain = "test_compare_compressed_db1_plain.txt";
        let db2_plain = "test_compare_compressed_db2_plain.txt";

        let content1 = "hash1  sha256  normal  file1.txt\n\
                        hash2  sha256  normal  file2.txt\n\
                        hash3  sha256  normal  file3.txt\n";

        let content2 = "hash1  sha256  normal  file1.txt\n\
                        hash2_modified  sha256  normal  file2.txt\n\
                        hash3  sha256  normal  file3.txt\n\
                        hash4  sha256  normal  file4.txt\n";

        fs::write(db1_plain, content1).unwrap();
        fs::write(db2_plain, content2).unwrap();

        // Compress both databases
        let db1_compressed = DatabaseHandler::compress_database(Path::new(db1_plain)).unwrap();
        let db2_compressed = DatabaseHandler::compress_database(Path::new(db2_plain)).unwrap();

        // Test 1: Compare two compressed databases
        let engine = CompareEngine::new();
        let report = engine.compare(&db1_compressed, &db2_compressed).unwrap();

        assert_eq!(report.db1_total_files, 3);
        assert_eq!(report.db2_total_files, 4);
        assert_eq!(report.unchanged_files, 2);
        assert_eq!(report.changed_files.len(), 1);
        assert_eq!(report.added_files.len(), 1);

        // Test 2: Compare compressed vs plain text
        let report2 = engine
            .compare(&db1_compressed, Path::new(db2_plain))
            .unwrap();

        assert_eq!(report2.db1_total_files, 3);
        assert_eq!(report2.db2_total_files, 4);
        assert_eq!(report2.unchanged_files, 2);
        assert_eq!(report2.changed_files.len(), 1);

        // Test 3: Compare plain text vs compressed
        let report3 = engine
            .compare(Path::new(db1_plain), &db2_compressed)
            .unwrap();

        assert_eq!(report3.db1_total_files, 3);
        assert_eq!(report3.db2_total_files, 4);
        assert_eq!(report3.unchanged_files, 2);
        assert_eq!(report3.changed_files.len(), 1);

        // Cleanup
        fs::remove_file(db1_plain).unwrap();
        fs::remove_file(db2_plain).unwrap();
        fs::remove_file(db1_compressed).unwrap();
        fs::remove_file(db2_compressed).unwrap();
    }

    #[test]
    fn test_compare_report_summary_correctness() {
        // Test that summary counts are mathematically consistent
        let db1_path = "test_compare_summary_db1.txt";
        let db2_path = "test_compare_summary_db2.txt";

        let content1 = "hash1  sha256  normal  unchanged.txt\n\
                        hash2  sha256  normal  changed.txt\n\
                        hash3  sha256  normal  removed.txt\n";

        let content2 = "hash1  sha256  normal  unchanged.txt\n\
                        hash_new  sha256  normal  changed.txt\n\
                        hash4  sha256  normal  added.txt\n";

        fs::write(db1_path, content1).unwrap();
        fs::write(db2_path, content2).unwrap();

        let engine = CompareEngine::new();
        let report = engine
            .compare(Path::new(db1_path), Path::new(db2_path))
            .unwrap();

        // Verify mathematical consistency:
        // unchanged + changed + removed = db1_total
        assert_eq!(
            report.unchanged_files + report.changed_files.len() + report.removed_files.len(),
            report.db1_total_files
        );

        // unchanged + changed + added = db2_total
        assert_eq!(
            report.unchanged_files + report.changed_files.len() + report.added_files.len(),
            report.db2_total_files
        );

        fs::remove_file(db1_path).unwrap();
        fs::remove_file(db2_path).unwrap();
    }

    #[test]
    fn test_to_hashdeep_format() {
        let db1_path = "test_hashdeep_format_db1.txt";
        let db2_path = "test_hashdeep_format_db2.txt";

        let content1 = "hash1  sha256  normal  unchanged.txt\n\
                        hash_old  sha256  normal  changed.txt\n\
                        hash_removed  sha256  normal  removed.txt\n";

        let content2 = "hash1  sha256  normal  unchanged.txt\n\
                        hash_new  sha256  normal  changed.txt\n\
                        hash_added  sha256  normal  added.txt\n";

        fs::write(db1_path, content1).unwrap();
        fs::write(db2_path, content2).unwrap();

        let engine = CompareEngine::new();
        let report = engine
            .compare(Path::new(db1_path), Path::new(db2_path))
            .unwrap();

        let hashdeep_output = report.to_hashdeep();

        // Verify audit failed header
        assert!(hashdeep_output.contains("hashdeep: Audit failed"));

        // Verify summary counts
        assert!(hashdeep_output.contains("Files matched: 1"));
        assert!(hashdeep_output.contains("Files modified: 1"));
        assert!(hashdeep_output.contains("New files found: 1"));
        assert!(hashdeep_output.contains("Known files not found: 1"));

        // Verify modified file entry with both hashes
        assert!(hashdeep_output.contains("Modified files:"));
        assert!(hashdeep_output.contains("changed.txt"));
        assert!(hashdeep_output.contains("Known hash:"));
        assert!(hashdeep_output.contains("hash_old"));
        assert!(hashdeep_output.contains("Computed hash:"));
        assert!(hashdeep_output.contains("hash_new"));

        // Verify new file entry
        assert!(hashdeep_output.contains("New files:"));
        assert!(hashdeep_output.contains("added.txt"));

        // Verify not found file entry
        assert!(hashdeep_output.contains("Known files not found:"));
        assert!(hashdeep_output.contains("removed.txt"));

        fs::remove_file(db1_path).unwrap();
        fs::remove_file(db2_path).unwrap();
    }

    #[test]
    fn test_to_hashdeep_format_audit_passed() {
        let db1_path = "test_hashdeep_audit_passed_db1.txt";
        let db2_path = "test_hashdeep_audit_passed_db2.txt";

        // Identical databases should result in audit passed
        let content = "hash1  sha256  normal  file1.txt\n\
                       hash2  sha256  normal  file2.txt\n";

        fs::write(db1_path, content).unwrap();
        fs::write(db2_path, content).unwrap();

        let engine = CompareEngine::new();
        let report = engine
            .compare(Path::new(db1_path), Path::new(db2_path))
            .unwrap();

        let hashdeep_output = report.to_hashdeep();

        // Verify audit passed
        assert!(hashdeep_output.contains("hashdeep: Audit passed"));
        assert!(!hashdeep_output.contains("hashdeep: Audit failed"));

        fs::remove_file(db1_path).unwrap();
        fs::remove_file(db2_path).unwrap();
    }
}
