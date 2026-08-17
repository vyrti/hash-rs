use std::path::Path;

use quichash_core::compare::CompareEngine;
use quichash_core::error::HashUtilityError;

/// Handle the compare command: compare two hash databases
pub fn handle_compare_command(
    database1: &Path,
    database2: &Path,
    output: Option<&Path>,
    format: &str,
) -> Result<(), HashUtilityError> {
    // Create compare engine and run comparison
    let engine = CompareEngine::new();
    let report = engine.compare(database1, database2)?;

    // Format output based on requested format
    let output_content = match format.to_lowercase().as_str() {
        "plain-text" | "plain" | "text" => report.to_plain_text(),
        "json" => report
            .to_json()
            .map_err(|e| HashUtilityError::InvalidArguments {
                message: format!("Failed to serialize JSON: {}", e),
            })?,
        "hashdeep" => report.to_hashdeep(),
        _ => {
            return Err(HashUtilityError::InvalidArguments {
                message: format!(
                    "Invalid format '{}'. Valid formats are: plain-text, json, hashdeep",
                    format
                ),
            });
        }
    };

    // Write to output destination
    if let Some(output_path) = output {
        // Write to file
        std::fs::write(output_path, output_content).map_err(|e| {
            HashUtilityError::from_io_error(e, "writing output", Some(output_path.to_path_buf()))
        })?;

        // Display summary to stdout
        println!("Comparison report written to: {}", output_path.display());
        println!("\nDatabases:");
        println!(
            "  DB1: {} ({} files)",
            report.db1_info.path.display(),
            report.db1_total_files
        );
        println!(
            "  DB2: {} ({} files)",
            report.db2_info.path.display(),
            report.db2_total_files
        );
        println!("\nSummary:");
        println!("  Unchanged:  {} files", report.unchanged_files);
        println!("  Changed:    {} files", report.changed_files.len());
        println!("  Moved:      {} files", report.moved_files.len());
        println!("  Removed:    {} files", report.removed_files.len());
        println!("  Added:      {} files", report.added_files.len());
    } else {
        // Write to stdout
        print!("{}", output_content);
    }

    Ok(())
}
