use std::path::Path;

use quichash_core::dedup::DedupEngine;
use quichash_core::error::HashUtilityError;

/// Handle the dedup command: find duplicate files in a directory
pub fn handle_dedup_command(
    directory: &Path,
    fast: bool,
    output: Option<&Path>,
    json: bool,
) -> Result<(), HashUtilityError> {
    // Create dedup engine with appropriate settings
    let engine = DedupEngine::new().with_fast_mode(fast).with_parallel(true); // Always use parallel for better performance

    // Find duplicates
    let report = engine.find_duplicates(directory)?;

    // Format output based on json flag
    let output_content = if json {
        report
            .to_json()
            .map_err(|e| HashUtilityError::InvalidArguments {
                message: format!("Failed to serialize JSON: {}", e),
            })?
    } else {
        // For plain text, we'll use the display method which prints directly
        // So we need to capture it as a string
        use std::fmt::Write;
        let mut output_str = String::new();

        // Manually format the report
        writeln!(&mut output_str, "\n=== Duplicate Files Report ===\n").unwrap();
        writeln!(&mut output_str, "Summary:").unwrap();
        writeln!(
            &mut output_str,
            "  Files scanned:     {}",
            report.stats.files_scanned
        )
        .unwrap();
        writeln!(
            &mut output_str,
            "  Files failed:      {}",
            report.stats.files_failed
        )
        .unwrap();
        writeln!(
            &mut output_str,
            "  Total bytes:       {} ({:.2} MB)",
            report.stats.total_bytes,
            report.stats.total_bytes as f64 / 1_048_576.0
        )
        .unwrap();
        writeln!(
            &mut output_str,
            "  Duplicate groups:  {}",
            report.stats.duplicate_groups
        )
        .unwrap();
        writeln!(
            &mut output_str,
            "  Duplicate files:   {}",
            report.stats.duplicate_files
        )
        .unwrap();
        writeln!(
            &mut output_str,
            "  Wasted space:      {} ({:.2} MB)",
            report.stats.wasted_space,
            report.stats.wasted_space as f64 / 1_048_576.0
        )
        .unwrap();
        writeln!(
            &mut output_str,
            "  Duration:          {:.2}s",
            report.stats.duration.as_secs_f64()
        )
        .unwrap();

        if report.stats.duration.as_secs_f64() > 0.0 {
            let throughput_mbps = (report.stats.total_bytes as f64 / 1_048_576.0)
                / report.stats.duration.as_secs_f64();
            writeln!(
                &mut output_str,
                "  Throughput:        {:.2} MB/s",
                throughput_mbps
            )
            .unwrap();
        }

        if !report.duplicate_groups.is_empty() {
            writeln!(
                &mut output_str,
                "\nDuplicate Groups (sorted by wasted space):"
            )
            .unwrap();
            for group in &report.duplicate_groups {
                writeln!(
                    &mut output_str,
                    "\n  Hash: {} ({} files, {} bytes each, {} bytes wasted)",
                    group.hash, group.count, group.file_size, group.wasted_space
                )
                .unwrap();
                for path in &group.paths {
                    writeln!(&mut output_str, "    {}", path.display()).unwrap();
                }
            }
        } else {
            writeln!(&mut output_str, "\nNo duplicate files found.").unwrap();
        }

        writeln!(&mut output_str).unwrap();
        output_str
    };

    // Write to output destination
    if let Some(output_path) = output {
        // Write to file
        std::fs::write(output_path, output_content).map_err(|e| {
            HashUtilityError::from_io_error(e, "writing output", Some(output_path.to_path_buf()))
        })?;

        // Display summary to stdout
        println!("Dedup report written to: {}", output_path.display());
        println!("\nSummary:");
        println!("  Files scanned:     {}", report.stats.files_scanned);
        println!("  Duplicate groups:  {}", report.stats.duplicate_groups);
        println!("  Duplicate files:   {}", report.stats.duplicate_files);
        println!(
            "  Wasted space:      {} ({:.2} MB)",
            report.stats.wasted_space,
            report.stats.wasted_space as f64 / 1_048_576.0
        );
    } else {
        // Write to stdout
        print!("{}", output_content);
    }

    Ok(())
}
