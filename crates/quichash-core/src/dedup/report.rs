use std::path::PathBuf;
use std::time::Duration;

/// Statistics collected during a dedup scan
#[derive(Debug, Clone, serde::Serialize)]
pub struct DedupStats {
    /// Number of regular files considered.
    pub files_scanned: usize,
    /// Number of files that could not be processed.
    pub files_failed: usize,
    /// Sum of file sizes considered.
    pub total_bytes: u64,
    /// Number of digest groups containing duplicates.
    pub duplicate_groups: usize,
    /// Number of files belonging to duplicate groups.
    pub duplicate_files: usize,
    /// Bytes theoretically reclaimable by retaining one file per group.
    pub wasted_space: u64,
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

/// Report of duplicate files found in a directory
#[derive(Debug, Clone, serde::Serialize)]
pub struct DedupReport {
    /// Aggregate scan and duplicate statistics.
    pub stats: DedupStats,
    /// Duplicate groups including size information.
    pub duplicate_groups: Vec<DuplicateGroupWithSize>,
}

/// Duplicate group with file size information
#[derive(Debug, Clone, serde::Serialize)]
pub struct DuplicateGroupWithSize {
    /// Digest shared by the group.
    pub hash: String,
    /// Paths with the shared digest.
    pub paths: Vec<PathBuf>,
    /// Number of paths in the group.
    pub count: usize,
    /// Size of each file in the group.
    pub file_size: u64,
    /// Reclaimable bytes if all but one copy were removed.
    pub wasted_space: u64, // (count - 1) * file_size
}

impl DedupReport {
    /// Legacy display hook retained for API compatibility.
    ///
    /// The core crate does not write terminal output; consume the report fields
    /// or [`Self::to_json`] in the embedding application.
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

    /// Serialize this report as pretty-printed JSON.
    #[cfg(feature = "reporting")]
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
