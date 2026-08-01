//! Manifest analysis.
// Analyzes a single hash database and generates statistics

use crate::database::{DatabaseFormat, DatabaseHandler};
use crate::error::HashUtilityError;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// A group of duplicate files (same hash)
#[derive(Debug, Clone, serde::Serialize)]
pub struct DuplicateGroup {
    /// Digest shared by every path in the group.
    pub hash: String,
    /// Paths with the shared digest.
    pub paths: Vec<PathBuf>,
    /// Number of paths in the group.
    pub count: usize,
    /// File size in bytes (only available for hashdeep format)
    pub file_size: Option<u64>,
    /// Wasted space: (count - 1) * file_size
    pub wasted_space: Option<u64>,
}

/// Database entry with optional size information
#[derive(Debug, Clone)]
pub struct EntryWithSize {
    /// Lowercase hexadecimal digest.
    pub hash: String,
    /// Algorithm recorded for the digest.
    pub algorithm: String,
    /// Whether sampled hashing produced the digest.
    pub fast_mode: bool,
    /// File length when the source format provides it.
    pub file_size: Option<u64>,
}

/// Statistics about the analyzed database
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalyzeStats {
    /// Number of file entries read from the database.
    pub total_files: usize,
    /// Number of distinct digest strings.
    pub unique_hashes: usize,
    /// Number of digest groups containing multiple paths.
    pub duplicate_groups: usize,
    /// Total paths belonging to duplicate groups.
    pub duplicate_files: usize,
    /// Size of the database file itself.
    pub database_file_size: u64,
    /// Detected source format name.
    pub database_format: String,
    /// Distinct algorithms recorded by the database.
    pub algorithms: Vec<String>,
    /// Number of sampled-mode entries.
    pub fast_mode_files: usize,
    /// Number of full-mode entries.
    pub normal_mode_files: usize,
    /// Total size of all files (only for hashdeep format)
    pub total_file_size: Option<u64>,
    /// Potential space savings from deduplication
    pub potential_savings: Option<u64>,
}

/// Complete analysis report
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalyzeReport {
    /// Database that was analyzed.
    pub database_path: PathBuf,
    /// Aggregate database statistics.
    pub stats: AnalyzeStats,
    /// Groups of paths sharing a digest.
    pub duplicate_groups: Vec<DuplicateGroup>,
}

impl AnalyzeReport {
    /// Format the report as plain text
    pub fn to_plain_text(&self) -> String {
        let mut output = String::new();

        output.push_str("\n=== Database Analysis Report ===\n\n");

        // Database info
        output.push_str(&format!("Database: {}\n", self.database_path.display()));
        output.push_str(&format!("Format:   {}\n", self.stats.database_format));
        output.push_str(&format!(
            "Size:     {}\n",
            format_size(self.stats.database_file_size)
        ));

        // Summary
        output.push_str("\nSummary:\n");
        output.push_str(&format!("  Total files:    {}\n", self.stats.total_files));
        output.push_str(&format!("  Unique hashes:  {}\n", self.stats.unique_hashes));
        output.push_str(&format!(
            "  Algorithms:     {}\n",
            self.stats.algorithms.join(", ")
        ));
        output.push_str(&format!(
            "  Fast mode:      {} files\n",
            self.stats.fast_mode_files
        ));
        output.push_str(&format!(
            "  Normal mode:    {} files\n",
            self.stats.normal_mode_files
        ));

        // File sizes (if available)
        if let Some(total_size) = self.stats.total_file_size {
            output.push_str("\nFile Sizes:\n");
            output.push_str(&format!("  Total size:     {}\n", format_size(total_size)));
        }

        // Duplicates
        output.push_str("\nDuplicates:\n");
        output.push_str(&format!(
            "  Duplicate groups: {}\n",
            self.stats.duplicate_groups
        ));
        output.push_str(&format!(
            "  Duplicate files:  {}\n",
            self.stats.duplicate_files
        ));
        if let Some(savings) = self.stats.potential_savings {
            output.push_str(&format!("  Potential savings: {}\n", format_size(savings)));
        }

        // Duplicate details
        if !self.duplicate_groups.is_empty() {
            output.push_str("\nDuplicate Groups:\n");
            for group in &self.duplicate_groups {
                let size_info = match group.file_size {
                    Some(size) => format!(" ({} each)", format_size(size)),
                    None => String::new(),
                };
                output.push_str(&format!(
                    "  Hash: {}...{} ({} files{})\n",
                    &group.hash[..8.min(group.hash.len())],
                    &group.hash[group.hash.len().saturating_sub(8)..],
                    group.count,
                    size_info
                ));
                for path in &group.paths {
                    output.push_str(&format!("    {}\n", path.display()));
                }
            }
        }

        output.push('\n');
        output
    }

    /// Format the report as JSON
    #[cfg(feature = "reporting")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        #[derive(serde::Serialize)]
        struct JsonOutput {
            metadata: Metadata,
            database: DatabaseInfo,
            summary: Summary,
            file_sizes: FileSizes,
            duplicates: DuplicatesInfo,
            duplicate_groups: Vec<DuplicateGroupJson>,
        }

        #[derive(serde::Serialize)]
        struct Metadata {
            timestamp: String,
        }

        #[derive(serde::Serialize)]
        struct DatabaseInfo {
            path: String,
            format: String,
            size_bytes: u64,
        }

        #[derive(serde::Serialize)]
        struct Summary {
            total_files: usize,
            unique_hashes: usize,
            algorithms: Vec<String>,
            fast_mode_files: usize,
            normal_mode_files: usize,
        }

        #[derive(serde::Serialize)]
        struct FileSizes {
            available: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            total_bytes: Option<u64>,
        }

        #[derive(serde::Serialize)]
        struct DuplicatesInfo {
            groups: usize,
            files: usize,
            #[serde(skip_serializing_if = "Option::is_none")]
            potential_savings_bytes: Option<u64>,
        }

        #[derive(serde::Serialize)]
        struct DuplicateGroupJson {
            hash: String,
            count: usize,
            #[serde(skip_serializing_if = "Option::is_none")]
            file_size_bytes: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            wasted_space_bytes: Option<u64>,
            paths: Vec<String>,
        }

        let output = JsonOutput {
            metadata: Metadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
            database: DatabaseInfo {
                path: self.database_path.display().to_string(),
                format: self.stats.database_format.clone(),
                size_bytes: self.stats.database_file_size,
            },
            summary: Summary {
                total_files: self.stats.total_files,
                unique_hashes: self.stats.unique_hashes,
                algorithms: self.stats.algorithms.clone(),
                fast_mode_files: self.stats.fast_mode_files,
                normal_mode_files: self.stats.normal_mode_files,
            },
            file_sizes: FileSizes {
                available: self.stats.total_file_size.is_some(),
                total_bytes: self.stats.total_file_size,
            },
            duplicates: DuplicatesInfo {
                groups: self.stats.duplicate_groups,
                files: self.stats.duplicate_files,
                potential_savings_bytes: self.stats.potential_savings,
            },
            duplicate_groups: self
                .duplicate_groups
                .iter()
                .map(|g| DuplicateGroupJson {
                    hash: g.hash.clone(),
                    count: g.count,
                    file_size_bytes: g.file_size,
                    wasted_space_bytes: g.wasted_space,
                    paths: g.paths.iter().map(|p| p.display().to_string()).collect(),
                })
                .collect(),
        };

        serde_json::to_string_pretty(&output)
    }
}

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
        let entries = Self::read_database_with_sizes(database_path, format)?;

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
        let duplicate_groups = Self::find_duplicates(&entries);
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

    /// Read database and extract size information if available
    fn read_database_with_sizes(
        path: &Path,
        format: DatabaseFormat,
    ) -> Result<HashMap<PathBuf, EntryWithSize>, HashUtilityError> {
        match format {
            DatabaseFormat::Quichash => {
                // QuicHash format doesn't have sizes
                let db = DatabaseHandler::read_database(path)?;
                Ok(db
                    .into_iter()
                    .map(|(path, entry)| {
                        (
                            path,
                            EntryWithSize {
                                hash: entry.hash,
                                algorithm: entry.algorithm,
                                fast_mode: entry.fast_mode,
                                file_size: None,
                            },
                        )
                    })
                    .collect())
            }
            DatabaseFormat::Hashdeep => {
                // Parse hashdeep format with sizes
                Self::read_hashdeep_with_sizes(path)
            }
        }
    }

    /// Read hashdeep format database and extract file sizes
    fn read_hashdeep_with_sizes(
        path: &Path,
    ) -> Result<HashMap<PathBuf, EntryWithSize>, HashUtilityError> {
        use std::io::BufRead;

        let file = std::fs::File::open(path).map_err(|e| {
            HashUtilityError::from_io_error(e, "opening database", Some(path.to_path_buf()))
        })?;

        let reader: Box<dyn BufRead> = if DatabaseHandler::is_compressed(path) {
            #[cfg(feature = "xz")]
            {
                Box::new(std::io::BufReader::new(xz2::read::XzDecoder::new(file)))
            }
            #[cfg(not(feature = "xz"))]
            {
                let _ = file;
                return Err(HashUtilityError::InvalidArguments {
                    message: format!(
                        "reading '{}' requires the 'xz' Cargo feature",
                        path.display()
                    ),
                });
            }
        } else {
            Box::new(std::io::BufReader::new(file))
        };

        let mut entries = HashMap::new();
        let mut algorithms: Vec<String> = Vec::new();

        for line_result in reader.lines() {
            let line = line_result.map_err(|e| {
                HashUtilityError::from_io_error(e, "reading database", Some(path.to_path_buf()))
            })?;

            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Parse header to get algorithm names
            if trimmed.starts_with("%%%%") && trimmed.contains(',') {
                let header_parts: Vec<&str> = trimmed.split_whitespace().collect();
                if header_parts.len() >= 2 {
                    let fields: Vec<&str> = header_parts[1].split(',').collect();
                    if fields.len() >= 3 {
                        algorithms = fields[1..fields.len() - 1]
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                    }
                }
                continue;
            }

            // Skip other header lines
            if trimmed.starts_with('%') {
                continue;
            }

            let expected_hash_count = (!algorithms.is_empty()).then_some(algorithms.len());
            let Some(record) = DatabaseHandler::parse_hashdeep_record(&line, expected_hash_count)
            else {
                continue;
            };

            // Use the first digest for compatibility with the analysis engine.
            let hash = &record.hashes[0];
            if hash.is_empty() {
                continue;
            }

            let algorithm = algorithms
                .first()
                .cloned()
                .unwrap_or_else(|| infer_algorithm_from_hash(hash));

            let file_path = crate::path_utils::parse_database_path(&record.filename);
            entries.insert(
                file_path,
                EntryWithSize {
                    hash: hash.clone(),
                    algorithm,
                    fast_mode: false,
                    file_size: Some(record.size),
                },
            );
        }

        Ok(entries)
    }

    /// Find duplicate files (same hash, different paths)
    fn find_duplicates(entries: &HashMap<PathBuf, EntryWithSize>) -> Vec<DuplicateGroup> {
        // Group paths by hash
        let mut hash_to_entries: HashMap<String, Vec<(&PathBuf, &EntryWithSize)>> = HashMap::new();

        for (path, entry) in entries {
            hash_to_entries
                .entry(entry.hash.clone())
                .or_default()
                .push((path, entry));
        }

        // Filter to only groups with duplicates
        let mut duplicates: Vec<DuplicateGroup> = hash_to_entries
            .into_iter()
            .filter(|(_, paths)| paths.len() > 1)
            .map(|(hash, mut items)| {
                items.sort_by(|a, b| a.0.cmp(b.0));
                let count = items.len();
                let file_size = items.first().and_then(|(_, e)| e.file_size);
                let wasted_space = file_size.map(|s| s * (count as u64 - 1));

                DuplicateGroup {
                    hash,
                    paths: items.into_iter().map(|(p, _)| p.clone()).collect(),
                    count,
                    file_size,
                    wasted_space,
                }
            })
            .collect();

        // Sort by wasted space (descending) then by hash
        duplicates.sort_by(|a, b| {
            b.wasted_space
                .cmp(&a.wasted_space)
                .then_with(|| a.hash.cmp(&b.hash))
        });

        duplicates
    }
}

/// Infer hash algorithm from hash string length
fn infer_algorithm_from_hash(hash: &str) -> String {
    match hash.len() {
        32 => "md5".to_string(),
        40 => "sha1".to_string(),
        56 => "sha224".to_string(),
        64 => "sha256".to_string(),
        96 => "sha384".to_string(),
        128 => "sha512".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Format byte size as human-readable string
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_analyze_quichash_format() {
        let db_path = "test_analyze_quichash.qh";
        let content = "hash1  sha256  normal  file1.txt\n\
                       hash2  sha256  normal  file2.txt\n\
                       hash1  sha256  normal  file1_copy.txt\n";
        fs::write(db_path, content).unwrap();

        let engine = AnalyzeEngine::new();
        let report = engine.analyze(Path::new(db_path)).unwrap();

        assert_eq!(report.stats.total_files, 3);
        assert_eq!(report.stats.unique_hashes, 2);
        assert_eq!(report.stats.duplicate_groups, 1);
        assert_eq!(report.stats.duplicate_files, 2);
        assert!(report.stats.total_file_size.is_none()); // QuicHash format has no sizes

        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn test_analyze_hashdeep_format() {
        let db_path = "test_analyze_hashdeep.txt";
        let content = "%%%% HASHDEEP-1.0\n\
                       %%%% size,sha256,filename\n\
                       ## Invoked from: test\n\
                       ##\n\
                       1000,hash1,file1.txt\n\
                       2000,hash2,file2.txt\n\
                       1000,hash1,file1_copy.txt\n";
        fs::write(db_path, content).unwrap();

        let engine = AnalyzeEngine::new();
        let report = engine.analyze(Path::new(db_path)).unwrap();

        assert_eq!(report.stats.total_files, 3);
        assert_eq!(report.stats.unique_hashes, 2);
        assert_eq!(report.stats.duplicate_groups, 1);
        assert_eq!(report.stats.total_file_size, Some(4000)); // 1000 + 2000 + 1000
        assert_eq!(report.stats.potential_savings, Some(1000)); // One duplicate of 1000 bytes

        fs::remove_file(db_path).unwrap();
    }

    #[test]
    fn test_analyze_hashdeep_format_with_commas_in_filename() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let content = "%%%% HASHDEEP-1.0\n\
                       %%%% size,sha256,filename\n\
                       ## Invoked from: test\n\
                       ##\n\
                       1000,hash1,file,one.txt\n\
                       1000,hash1,file,two.txt\n";
        fs::write(temporary.path(), content).unwrap();

        let report = AnalyzeEngine::new().analyze(temporary.path()).unwrap();
        assert_eq!(report.stats.total_files, 2);
        assert_eq!(report.stats.duplicate_groups, 1);
        assert_eq!(report.stats.total_file_size, Some(2000));
        assert!(report.duplicate_groups[0]
            .paths
            .contains(&PathBuf::from("file,one.txt")));
        assert!(report.duplicate_groups[0]
            .paths
            .contains(&PathBuf::from("file,two.txt")));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 bytes");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1048576), "1.00 MB");
        assert_eq!(format_size(1073741824), "1.00 GB");
    }
}
