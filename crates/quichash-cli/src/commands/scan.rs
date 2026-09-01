use std::path::Path;

use quichash_core::database::{self, DatabaseFormat};
use quichash_core::error::HashUtilityError;
use quichash_core::scan::{self, ScanEngine};
use quichash_core::wildcard;

/// Handle the scan command: scan directory and write database
#[allow(clippy::too_many_arguments)]
pub fn handle_scan_command(
    directory_pattern: &str,
    algorithm: &str,
    output: &Path,
    parallel: bool,
    fast: bool,
    format_str: &str,
    json: bool,
    compress: bool,
) -> Result<(), HashUtilityError> {
    // Parse format string
    let format = match format_str.to_lowercase().as_str() {
        "quichash" => DatabaseFormat::Quichash,
        "hashdeep" => DatabaseFormat::Hashdeep,
        _ => {
            return Err(HashUtilityError::InvalidArguments {
                message: format!(
                    "Invalid format '{}'. Valid formats are: quichash, hashdeep",
                    format_str
                ),
            });
        }
    };

    if compress && format == DatabaseFormat::Hashdeep {
        return Err(HashUtilityError::InvalidArguments {
            message: "hashdeep output cannot be compressed; use QuicHash format with --compress"
                .to_owned(),
        });
    }

    let output = database::DatabaseHandler::canonical_output_path(output, format, false)?;
    let final_output_path =
        database::DatabaseHandler::canonical_output_path(&output, format, compress)?;

    // Expand wildcard pattern to get list of directories
    let directories = wildcard::expand_pattern(directory_pattern)?;

    // Verify all matched paths are directories
    for dir in &directories {
        if !dir.is_dir() {
            return Err(HashUtilityError::InvalidArguments {
                message: format!("Path '{}' is not a directory", dir.display()),
            });
        }
    }

    if !json {
        for directory in &directories {
            println!("Scanning directory: {}", directory.display());
        }
        if fast {
            println!("Fast mode enabled: sampling first, middle, and last 100MB of large files");
        }
    }

    let engine = ScanEngine::with_parallel(parallel)
        .with_fast_mode(fast)
        .with_format(format)
        .with_excluded_output(final_output_path);

    // Scan all matched directories and aggregate stats
    let mut total_stats = scan::ScanStats {
        files_processed: 0,
        files_failed: 0,
        total_bytes: 0,
        duration: std::time::Duration::new(0, 0),
    };

    // For multiple directories, we need to handle output differently
    if directories.len() > 1 {
        // Create the output file first (this will overwrite if it exists)
        std::fs::File::create(&output).map_err(|e| {
            HashUtilityError::from_io_error(e, "creating output file", Some(output.clone()))
        })?;

        // Scan each directory and append to the output file
        for (idx, directory) in directories.iter().enumerate() {
            // For the first directory, use normal mode (create/overwrite)
            // For subsequent directories, we need to append
            let temp_output = if idx == 0 {
                output.clone()
            } else {
                // Create a temporary file for this directory's results

                output.with_extension(format!("tmp{}", idx))
            };

            let stats = engine.scan_directory(directory, algorithm, &temp_output)?;

            // If we used a temp file, append its contents to the main output
            if idx > 0 {
                let mut temp_file = std::fs::File::open(&temp_output).map_err(|e| {
                    HashUtilityError::from_io_error(
                        e,
                        "reading temp file",
                        Some(temp_output.clone()),
                    )
                })?;

                let mut output_file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&output)
                    .map_err(|e| {
                        HashUtilityError::from_io_error(
                            e,
                            "opening output file for append",
                            Some(output.clone()),
                        )
                    })?;

                std::io::copy(&mut temp_file, &mut output_file).map_err(|e| {
                    HashUtilityError::from_io_error(
                        e,
                        "appending to output file",
                        Some(output.clone()),
                    )
                })?;

                // Remove the temp file
                std::fs::remove_file(&temp_output).ok();
            }

            total_stats.files_processed += stats.files_processed;
            total_stats.files_failed += stats.files_failed;
            total_stats.total_bytes += stats.total_bytes;
            total_stats.duration += stats.duration;
        }
    } else {
        // Single directory - use normal scan
        let stats = engine.scan_directory(&directories[0], algorithm, &output)?;
        total_stats = stats;
    }

    let stats = total_stats;

    // Compress the database if requested
    let final_output = if compress {
        use database::DatabaseHandler;

        if !json {
            println!("Compressing database...");
        }
        let compressed_path = DatabaseHandler::compress_database(&output)?;

        // Remove the uncompressed file
        std::fs::remove_file(&output).map_err(|e| {
            HashUtilityError::from_io_error(
                e,
                "removing uncompressed database",
                Some(output.clone()),
            )
        })?;

        if !json {
            println!("Database compressed to: {}", compressed_path.display());
        }
        compressed_path
    } else {
        output
    };

    if !json {
        println!("\nScan complete!");
        println!("Files processed: {}", stats.files_processed);
        println!("Files failed: {}", stats.files_failed);
        println!(
            "Total bytes: {} ({:.2} MB)",
            stats.total_bytes,
            stats.total_bytes as f64 / 1_048_576.0
        );
        println!("Duration: {:.2}s", stats.duration.as_secs_f64());
        if stats.duration.as_secs_f64() > 0.0 {
            println!(
                "Throughput: {:.2} MB/s",
                (stats.total_bytes as f64 / 1_048_576.0) / stats.duration.as_secs_f64()
            );
        }
        println!("Output written to: {}", final_output.display());
    }

    // Output results in JSON if requested
    if json {
        #[derive(serde::Serialize)]
        struct ScanOutput {
            stats: scan::ScanStats,
            metadata: ScanMetadata,
        }

        #[derive(serde::Serialize)]
        struct ScanMetadata {
            timestamp: String,
            directory_pattern: String,
            directories_scanned: Vec<std::path::PathBuf>,
            algorithm: String,
            output_file: std::path::PathBuf,
            parallel: bool,
            fast_mode: bool,
            format: String,
        }

        let output = ScanOutput {
            stats,
            metadata: ScanMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                directory_pattern: directory_pattern.to_string(),
                directories_scanned: directories,
                algorithm: algorithm.to_string(),
                output_file: final_output,
                parallel,
                fast_mode: fast,
                format: match format {
                    DatabaseFormat::Quichash => "quichash",
                    DatabaseFormat::Hashdeep => "hashdeep",
                }
                .to_owned(),
            },
        };

        let json_output = serde_json::to_string_pretty(&output).map_err(|e| {
            HashUtilityError::InvalidArguments {
                message: format!("Failed to serialize JSON: {}", e),
            }
        })?;

        println!("{}", json_output);
    }

    Ok(())
}
