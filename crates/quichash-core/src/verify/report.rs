use std::path::PathBuf;

/// Represents a hash mismatch between expected and actual values
#[derive(Debug, Clone, serde::Serialize)]
pub struct Mismatch {
    /// File whose digest differs.
    pub path: PathBuf,
    /// Digest stored in the database.
    pub expected: String,
    /// Digest recomputed from the file.
    pub actual: String,
}

/// Report of verification results
#[derive(Debug, serde::Serialize)]
pub struct VerifyReport {
    /// Number of files with matching digests.
    pub matches: usize,
    /// Files whose expected and actual digests differ.
    pub mismatches: Vec<Mismatch>,
    /// Database paths missing from the verified directory.
    pub missing_files: Vec<PathBuf>,
    /// Directory paths absent from the database.
    pub new_files: Vec<PathBuf>,
}

impl VerifyReport {
    /// Legacy display hook retained for API compatibility.
    ///
    /// The reusable core performs no terminal output. Consume the public report
    /// fields and render them in the embedding application.
    pub fn display(&self) {
        // Determine overall status
        let has_issues = !self.mismatches.is_empty()
            || !self.missing_files.is_empty()
            || !self.new_files.is_empty();

        // Display clear status banner
        println!("\n================================================================");
        if has_issues {
            println!("                  FILE CHANGES DETECTED                         ");
        } else {
            println!("                       ALL GOOD                                 ");
        }
        println!("================================================================\n");

        // Display summary counts
        println!("Verification Summary:");
        println!("  Matches:        {}", self.matches);
        println!("  Mismatches:     {}", self.mismatches.len());
        println!("  Missing files:  {}", self.missing_files.len());
        println!("  New files:      {}", self.new_files.len());

        // If everything is good, show success message and return
        if !has_issues {
            println!("\nAll files match the database. No changes detected.");
            let total_checked = self.matches + self.mismatches.len();
            println!("Total files verified: {}", total_checked);
            return;
        }

        // Show detailed information about issues
        if !self.mismatches.is_empty() {
            println!(
                "\n--- Files with Changed Hashes ({}) ---",
                self.mismatches.len()
            );
            for mismatch in &self.mismatches {
                println!();
                println!("  File: {}", mismatch.path.display());
                println!("    Expected: {}", mismatch.expected);
                println!("    Actual:   {}", mismatch.actual);
            }
            println!("----------------------------------------------------------------");
        }

        if !self.missing_files.is_empty() {
            println!("\n--- Deleted Files ({}) ---", self.missing_files.len());
            println!("(in database but not in filesystem)");
            for path in &self.missing_files {
                println!("  - {}", path.display());
            }
            println!("----------------------------------------------------------------");
        }

        if !self.new_files.is_empty() {
            println!("\n--- New Files ({}) ---", self.new_files.len());
            println!("(in filesystem but not in database)");
            for path in &self.new_files {
                println!("  + {}", path.display());
            }
            println!("----------------------------------------------------------------");
        }

        // Final summary
        println!("\n================================================================");
        let total_checked = self.matches + self.mismatches.len();
        let total_in_db = total_checked + self.missing_files.len();
        let total_in_fs = total_checked + self.new_files.len();
        println!("Total files checked:      {}", total_checked);
        println!("Total files in database:  {}", total_in_db);
        println!("Total files in filesystem: {}", total_in_fs);
        println!("================================================================");
    }
}
