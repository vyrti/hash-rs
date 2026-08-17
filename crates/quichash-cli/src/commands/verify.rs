use quichash_core::error::HashUtilityError;
use quichash_core::verify::{self, VerifyEngine};
use quichash_core::wildcard;

/// Handle the verify command: compare database with directory
pub fn handle_verify_command(
    database_pattern: &str,
    directory_pattern: &str,
    parallel: bool,
    json: bool,
) -> Result<(), HashUtilityError> {
    let engine = VerifyEngine::with_parallel(parallel);

    // Expand wildcard patterns
    let databases = wildcard::expand_pattern(database_pattern)?;
    let directories = wildcard::expand_pattern(directory_pattern)?;

    // Verify all matched paths are valid
    for db in &databases {
        if !db.is_file() {
            return Err(HashUtilityError::InvalidArguments {
                message: format!("Database path '{}' is not a file", db.display()),
            });
        }
    }

    for dir in &directories {
        if !dir.is_dir() {
            return Err(HashUtilityError::InvalidArguments {
                message: format!("Path '{}' is not a directory", dir.display()),
            });
        }
    }

    // Run verification for all combinations of databases and directories
    let mut all_reports = Vec::new();

    for database in &databases {
        for directory in &directories {
            let report = engine.verify(database, directory)?;
            all_reports.push((database.clone(), directory.clone(), report));
        }
    }

    // Aggregate results if multiple verifications were performed
    let (_database, _directory, report) = if all_reports.len() == 1 {
        // Single verification - use the report as-is
        let (db, dir, rep) = all_reports.into_iter().next().unwrap();
        (db, dir, rep)
    } else {
        // Multiple verifications - aggregate the reports
        let mut aggregated_report = verify::VerifyReport {
            matches: 0,
            mismatches: Vec::new(),
            missing_files: Vec::new(),
            new_files: Vec::new(),
        };

        for (db, dir, report) in &all_reports {
            if !json {
                println!(
                    "\n=== Verification: {} against {} ===",
                    db.display(),
                    dir.display()
                );
                display_verify_report(report);
            }

            aggregated_report.matches += report.matches;
            aggregated_report
                .mismatches
                .extend(report.mismatches.clone());
            aggregated_report
                .missing_files
                .extend(report.missing_files.clone());
            aggregated_report.new_files.extend(report.new_files.clone());
        }

        // Use the first database and directory for metadata
        let (first_db, first_dir, _) = all_reports.into_iter().next().unwrap();
        (first_db, first_dir, aggregated_report)
    };

    // Output results based on format
    if json {
        #[derive(serde::Serialize)]
        struct VerifyOutput {
            report: verify::VerifyReport,
            metadata: VerifyMetadata,
        }

        #[derive(serde::Serialize)]
        struct VerifyMetadata {
            timestamp: String,
            database_pattern: String,
            directory_pattern: String,
            databases_verified: Vec<std::path::PathBuf>,
            directories_verified: Vec<std::path::PathBuf>,
        }

        let output = VerifyOutput {
            report,
            metadata: VerifyMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                database_pattern: database_pattern.to_string(),
                directory_pattern: directory_pattern.to_string(),
                databases_verified: databases,
                directories_verified: directories,
            },
        };

        let json_output = serde_json::to_string_pretty(&output).map_err(|e| {
            HashUtilityError::InvalidArguments {
                message: format!("Failed to serialize JSON: {}", e),
            }
        })?;

        println!("{}", json_output);
    } else {
        // Display report in plain text
        display_verify_report(&report);
    }

    Ok(())
}

fn display_verify_report(report: &verify::VerifyReport) {
    let has_issues = !report.mismatches.is_empty()
        || !report.missing_files.is_empty()
        || !report.new_files.is_empty();
    println!("\n================================================================");
    println!(
        "{}",
        if has_issues {
            "                  FILE CHANGES DETECTED                         "
        } else {
            "                       ALL GOOD                                 "
        }
    );
    println!("================================================================\n");
    println!("Verification Summary:");
    println!("  Matches:        {}", report.matches);
    println!("  Mismatches:     {}", report.mismatches.len());
    println!("  Missing files:  {}", report.missing_files.len());
    println!("  New files:      {}", report.new_files.len());
    if !has_issues {
        println!("\nAll files match the database. No changes detected.");
        println!("Total files verified: {}", report.matches);
        return;
    }
    if !report.mismatches.is_empty() {
        println!(
            "\n--- Files with Changed Hashes ({}) ---",
            report.mismatches.len()
        );
        for mismatch in &report.mismatches {
            println!("\n  File: {}", mismatch.path.display());
            println!("    Expected: {}", mismatch.expected);
            println!("    Actual:   {}", mismatch.actual);
        }
        println!("----------------------------------------------------------------");
    }
    if !report.missing_files.is_empty() {
        println!("\n--- Deleted Files ({}) ---", report.missing_files.len());
        println!("(in database but not in filesystem)");
        for path in &report.missing_files {
            println!("  - {}", path.display());
        }
        println!("----------------------------------------------------------------");
    }
    if !report.new_files.is_empty() {
        println!("\n--- New Files ({}) ---", report.new_files.len());
        println!("(in filesystem but not in database)");
        for path in &report.new_files {
            println!("  + {}", path.display());
        }
        println!("----------------------------------------------------------------");
    }
    println!("\n================================================================");
    println!(
        "Total files checked:      {}",
        report.matches + report.mismatches.len()
    );
    println!(
        "Total files in database:  {}",
        report.matches + report.mismatches.len() + report.missing_files.len()
    );
    println!(
        "Total files in filesystem: {}",
        report.matches + report.mismatches.len() + report.new_files.len()
    );
    println!("================================================================");
}
