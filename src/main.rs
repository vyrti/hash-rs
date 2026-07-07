mod analyze;
mod benchmark;
mod cli;
mod compare;
mod database;
mod dedup;
mod error;
mod hash;
mod ignore_handler;
mod path_utils;
mod scan;
mod verify;
mod wildcard;

use benchmark::BenchmarkEngine;
use cli::{parse_args, Command};
use database::DatabaseFormat;
use error::HashUtilityError;
use hash::{HashComputer, HashRegistry};
use scan::ScanEngine;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process;
use verify::VerifyEngine;

fn main() {
    // Parse command-line arguments
    let cli = match parse_args() {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    // Check if running with no arguments and stdin is a terminal (not piped)
    // If so, show help instead of waiting for stdin
    if cli.command.is_none()
        && cli.file.is_none()
        && cli.text.is_none()
        && std::io::stdin().is_terminal()
    {
        // Show full help by simulating --help flag
        use clap::CommandFactory;
        let mut cmd = cli::Cli::command();
        cmd.print_help().unwrap();
        println!(); // Add newline after help
        process::exit(0);
    }

    // Dispatch to appropriate handler
    let result = match cli.command {
        Some(Command::Scan {
            directory,
            algorithm,
            database,
            hdd,
            fast,
            format,
            json,
            compress,
        }) => handle_scan_command(
            &directory, &algorithm, &database, !hdd, fast, &format, json, compress,
        ),
        Some(Command::Verify {
            database,
            directory,
            hdd,
            json,
        }) => handle_verify_command(&database, &directory, !hdd, json),
        Some(Command::Benchmark { size_mb, json }) => handle_benchmark_command(size_mb, json),
        Some(Command::List { json }) => handle_list_command(json),
        Some(Command::Compare {
            database1,
            database2,
            output,
            format,
        }) => handle_compare_command(&database1, &database2, output.as_deref(), &format),
        Some(Command::Version) => handle_version_command(),
        Some(Command::Dedup {
            directory,
            fast,
            output,
            json,
        }) => handle_dedup_command(&directory, fast, output.as_deref(), json),
        Some(Command::Analyze {
            database,
            json,
            output,
        }) => handle_analyze_command(&database, json, output.as_deref()),
        None => {
            // No subcommand means hash mode (default)
            handle_hash_command(
                cli.file.as_deref(),
                cli.text.as_deref(),
                &cli.algorithms,
                cli.output.as_deref(),
                cli.fast,
                cli.json,
            )
        }
    };

    // Handle errors
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

/// Handle the hash command: compute and display hash(es) for a file, text, or stdin
fn handle_hash_command(
    file_pattern: Option<&str>,
    text: Option<&str>,
    algorithms: &[String],
    output: Option<&std::path::Path>,
    fast: bool,
    json: bool,
) -> Result<(), HashUtilityError> {
    let computer = HashComputer::new();

    // Compute hashes for all specified algorithms
    let results = match (file_pattern, text) {
        (Some(pattern), None) => {
            // Expand wildcard pattern to get list of files
            let files = wildcard::expand_pattern(pattern)?;

            // Determine if we should show progress (only for single file)
            let show_progress = files.len() == 1;

            // Hash all matched files
            let mut all_results = Vec::new();
            for file_path in files {
                if fast {
                    // Use fast mode for each algorithm
                    for algorithm in algorithms {
                        all_results.push(computer.compute_hash_fast(&file_path, algorithm)?);
                    }
                } else {
                    // Use normal mode with progress bar for single large files
                    let file_results = computer.compute_multiple_hashes_with_progress(
                        &file_path,
                        algorithms,
                        show_progress,
                    )?;
                    all_results.extend(file_results);
                }
            }
            all_results
        }
        (None, Some(text_input)) => {
            // Hash from text (fast mode not supported for text)
            if fast {
                return Err(HashUtilityError::InvalidArguments {
                    message: "Fast mode is not supported when hashing text".to_string(),
                });
            }
            computer.compute_multiple_hashes_text(text_input, algorithms)?
        }
        (None, None) => {
            // Hash from stdin (fast mode not supported for stdin)
            if fast {
                return Err(HashUtilityError::InvalidArguments {
                    message: "Fast mode is not supported when reading from stdin".to_string(),
                });
            }
            computer.compute_multiple_hashes_stdin(algorithms)?
        }
        (Some(_), Some(_)) => {
            // This should be prevented by clap's conflicts_with, but handle it anyway
            return Err(HashUtilityError::InvalidArguments {
                message: "Cannot specify both file and text arguments".to_string(),
            });
        }
    };

    // Format output based on json flag
    let output_content = if json {
        // JSON output
        #[derive(serde::Serialize)]
        struct HashOutput {
            files: Vec<hash::HashResult>,
            metadata: HashMetadata,
        }

        #[derive(serde::Serialize)]
        struct HashMetadata {
            timestamp: String,
            algorithms: Vec<String>,
            file_count: usize,
            fast_mode: bool,
        }

        let output = HashOutput {
            files: results.clone(),
            metadata: HashMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                algorithms: algorithms.to_vec(),
                file_count: {
                    use std::collections::HashSet;
                    results
                        .iter()
                        .map(|result| result.file_path.clone())
                        .collect::<HashSet<_>>()
                        .len()
                },
                fast_mode: fast,
            },
        };

        serde_json::to_string_pretty(&output).map_err(|e| HashUtilityError::InvalidArguments {
            message: format!("Failed to serialize JSON: {}", e),
        })?
    } else {
        // Plain text output
        let mut output_lines = Vec::new();

        // Group results by file path for better formatting when multiple algorithms are used
        if algorithms.len() > 1 {
            // Multiple algorithms - show algorithm name with each hash
            use std::collections::HashMap;
            let mut by_file: HashMap<PathBuf, Vec<&hash::HashResult>> = HashMap::new();
            for result in &results {
                by_file
                    .entry(result.file_path.clone())
                    .or_insert_with(Vec::new)
                    .push(result);
            }

            let num_files = by_file.len();
            for (file_path, file_results) in by_file {
                if num_files > 1 {
                    output_lines.push(format!("{}:", file_path.display()));
                }
                for result in file_results {
                    if num_files > 1 {
                        output_lines.push(format!(
                            "  {} ({})",
                            result.hash,
                            result.algorithm.to_uppercase()
                        ));
                    } else {
                        output_lines.push(format!(
                            "{} ({})  {}",
                            result.hash,
                            result.algorithm.to_uppercase(),
                            result.file_path.display()
                        ));
                    }
                }
                if num_files > 1 {
                    output_lines.push(String::new()); // Empty line between files
                }
            }
        } else {
            // Single algorithm - use traditional format
            for result in results {
                output_lines.push(format!("{}  {}", result.hash, result.file_path.display()));
            }
        }

        output_lines.join("\n") + "\n"
    };

    // Write to output destination
    if let Some(output_path) = output {
        // Write to file with better error context
        std::fs::write(output_path, output_content).map_err(|e| {
            HashUtilityError::from_io_error(e, "writing output", Some(output_path.to_path_buf()))
        })?;
    } else {
        // Write to stdout
        print!("{}", output_content);
    }

    Ok(())
}

/// Handle the scan command: scan directory and write database
fn handle_scan_command(
    directory_pattern: &str,
    algorithm: &str,
    output: &std::path::Path,
    parallel: bool,
    fast: bool,
    format_str: &str,
    json: bool,
    compress: bool,
) -> Result<(), HashUtilityError> {
    // Parse format string
    let format = match format_str.to_lowercase().as_str() {
        "standard" => DatabaseFormat::Standard,
        "hashdeep" => DatabaseFormat::Hashdeep,
        _ => {
            return Err(HashUtilityError::InvalidArguments {
                message: format!(
                    "Invalid format '{}'. Valid formats are: standard, hashdeep",
                    format_str
                ),
            });
        }
    };

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

    let engine = ScanEngine::with_parallel(parallel)
        .with_fast_mode(fast)
        .with_format(format)
        .with_quiet(json);

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
        std::fs::File::create(output).map_err(|e| {
            HashUtilityError::from_io_error(e, "creating output file", Some(output.to_path_buf()))
        })?;

        // Scan each directory and append to the output file
        for (idx, directory) in directories.iter().enumerate() {
            // For the first directory, use normal mode (create/overwrite)
            // For subsequent directories, we need to append
            let temp_output = if idx == 0 {
                output.to_path_buf()
            } else {
                // Create a temporary file for this directory's results
                let temp_path = output.with_extension(format!("tmp{}", idx));
                temp_path
            };

            let stats = engine.scan_directory(directory, algorithm, &temp_output)?;

            // If we used a temp file, append its contents to the main output
            if idx > 0 {
                let temp_contents = std::fs::read_to_string(&temp_output).map_err(|e| {
                    HashUtilityError::from_io_error(
                        e,
                        "reading temp file",
                        Some(temp_output.clone()),
                    )
                })?;

                use std::io::Write;
                let mut output_file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(output)
                    .map_err(|e| {
                        HashUtilityError::from_io_error(
                            e,
                            "opening output file for append",
                            Some(output.to_path_buf()),
                        )
                    })?;

                output_file
                    .write_all(temp_contents.as_bytes())
                    .map_err(|e| {
                        HashUtilityError::from_io_error(
                            e,
                            "appending to output file",
                            Some(output.to_path_buf()),
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
        let stats = engine.scan_directory(&directories[0], algorithm, output)?;
        total_stats = stats;
    }

    let stats = total_stats;

    // Compress the database if requested
    let final_output = if compress {
        use database::DatabaseHandler;

        if !json {
            println!("Compressing database...");
        }
        let compressed_path = DatabaseHandler::compress_database(output)?;

        // Remove the uncompressed file
        std::fs::remove_file(output).map_err(|e| {
            HashUtilityError::from_io_error(
                e,
                "removing uncompressed database",
                Some(output.to_path_buf()),
            )
        })?;

        if !json {
            println!("Database compressed to: {}", compressed_path.display());
        }
        compressed_path
    } else {
        output.to_path_buf()
    };

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
                format: format_str.to_string(),
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

/// Handle the verify command: compare database with directory
fn handle_verify_command(
    database_pattern: &str,
    directory_pattern: &str,
    parallel: bool,
    json: bool,
) -> Result<(), HashUtilityError> {
    let engine = VerifyEngine::with_parallel(parallel).with_quiet(json);

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
                report.display();
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

    let report = report;

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
        report.display();
    }

    Ok(())
}

/// Handle the benchmark command: run performance tests
fn handle_benchmark_command(size_mb: usize, json: bool) -> Result<(), HashUtilityError> {
    let engine = BenchmarkEngine::new();

    if !json {
        println!("Running benchmarks with {} MB of test data...", size_mb);
    }

    // Run benchmarks
    let results = engine.run_benchmarks(size_mb)?;

    // Output results based on format
    if json {
        #[derive(serde::Serialize)]
        struct BenchmarkOutput {
            results: Vec<benchmark::BenchmarkResult>,
            metadata: BenchmarkMetadata,
        }

        #[derive(serde::Serialize)]
        struct BenchmarkMetadata {
            timestamp: String,
            data_size_mb: usize,
            algorithm_count: usize,
        }

        let output = BenchmarkOutput {
            results: results.clone(),
            metadata: BenchmarkMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                data_size_mb: size_mb,
                algorithm_count: results.len(),
            },
        };

        let json_output = serde_json::to_string_pretty(&output).map_err(|e| {
            HashUtilityError::InvalidArguments {
                message: format!("Failed to serialize JSON: {}", e),
            }
        })?;

        println!("{}", json_output);
    } else {
        // Display results in plain text
        engine.display_results(&results);
    }

    Ok(())
}

/// Handle the list command: display available algorithms
fn handle_list_command(json: bool) -> Result<(), HashUtilityError> {
    let algorithms = HashRegistry::list_algorithms();

    if json {
        #[derive(serde::Serialize)]
        struct ListOutput {
            algorithms: Vec<hash::AlgorithmInfo>,
            metadata: ListMetadata,
        }

        #[derive(serde::Serialize)]
        struct ListMetadata {
            timestamp: String,
            algorithm_count: usize,
        }

        let output = ListOutput {
            algorithms: algorithms.clone(),
            metadata: ListMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                algorithm_count: algorithms.len(),
            },
        };

        let json_output = serde_json::to_string_pretty(&output).map_err(|e| {
            HashUtilityError::InvalidArguments {
                message: format!("Failed to serialize JSON: {}", e),
            }
        })?;

        println!("{}", json_output);
    } else {
        println!("\nAvailable Hash Algorithms:\n");
        println!(
            "{:<20} {:>12} {:>15} {:>15}",
            "Algorithm", "Output Bits", "Post-Quantum", "Cryptographic"
        );
        println!("{}", "-".repeat(65));

        for algo in algorithms {
            let pq_status = if algo.post_quantum { "Yes" } else { "No" };
            let crypto_status = if algo.cryptographic { "Yes" } else { "No" };
            println!(
                "{:<20} {:>12} {:>15} {:>15}",
                algo.name, algo.output_bits, pq_status, crypto_status
            );
        }

        println!();
    }

    Ok(())
}

/// Handle the compare command: compare two hash databases
fn handle_compare_command(
    database1: &Path,
    database2: &Path,
    output: Option<&Path>,
    format: &str,
) -> Result<(), HashUtilityError> {
    use compare::CompareEngine;

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

/// Handle the version command: display version information
fn handle_version_command() -> Result<(), HashUtilityError> {
    // Get version from Cargo.toml at compile time
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    // Display version in the format: hash v{version}
    println!("hash v{}", VERSION);

    Ok(())
}

/// Handle the dedup command: find duplicate files in a directory
fn handle_dedup_command(
    directory: &Path,
    fast: bool,
    output: Option<&Path>,
    json: bool,
) -> Result<(), HashUtilityError> {
    use dedup::DedupEngine;

    // Create dedup engine with appropriate settings
    let engine = DedupEngine::new()
        .with_fast_mode(fast)
        .with_parallel(true)
        .with_quiet(json); // Always use parallel for better performance

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

/// Handle the analyze command: analyze a hash database and display statistics
fn handle_analyze_command(
    database: &Path,
    json: bool,
    output: Option<&Path>,
) -> Result<(), HashUtilityError> {
    use analyze::AnalyzeEngine;

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
