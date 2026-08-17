use std::path::Path;

use quichash_core::analyze::AnalyzeEngine;
use quichash_core::error::HashUtilityError;

/// Handle the analyze command: analyze a hash database and display statistics
pub fn handle_analyze_command(
    database: &Path,
    json: bool,
    output: Option<&Path>,
) -> Result<(), HashUtilityError> {
    // Create analyze engine and run analysis
    let engine = AnalyzeEngine::new();
    let report = engine.analyze(database)?;

    // Format output based on json flag
    let output_content = if json {
        report
            .to_json()
            .map_err(|e| HashUtilityError::InvalidArguments {
                message: format!("Failed to serialize JSON: {}", e),
            })?
    } else {
        report.to_plain_text()
    };

    // Write to output destination
    if let Some(output_path) = output {
        // Write to file
        std::fs::write(output_path, output_content).map_err(|e| {
            HashUtilityError::from_io_error(e, "writing output", Some(output_path.to_path_buf()))
        })?;

        // Display summary to stdout
        println!("Analysis report written to: {}", output_path.display());
        println!("\nSummary:");
        println!("  Total files:        {}", report.stats.total_files);
        println!("  Unique hashes:      {}", report.stats.unique_hashes);
        println!("  Duplicate groups:   {}", report.stats.duplicate_groups);
        println!("  Duplicate files:    {}", report.stats.duplicate_files);
        if let Some(savings) = report.stats.potential_savings {
            println!(
                "  Potential savings:  {} ({:.2} MB)",
                savings,
                savings as f64 / 1_048_576.0
            );
        }
    } else {
        // Write to stdout
        print!("{}", output_content);
    }

    Ok(())
}
