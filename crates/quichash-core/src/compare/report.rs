use super::*;

/// Format bytes as human-readable size
pub(crate) fn format_size(bytes: u64) -> String {
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
