use std::path::PathBuf;

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

/// Format byte size as human-readable string
pub fn format_size(bytes: u64) -> String {
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
