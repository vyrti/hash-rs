use std::path::{Path, PathBuf};

use quichash_core::error::HashUtilityError;
use quichash_core::hash::{self, HashComputer};
use quichash_core::wildcard;

/// Handle the hash command: compute and display hash(es) for a file, text, or stdin
pub fn handle_hash_command(
    file_pattern: Option<&str>,
    text: Option<&str>,
    algorithms: &[String],
    output: Option<&Path>,
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

        let file_count = {
            use std::collections::HashSet;
            results
                .iter()
                .map(|result| &result.file_path)
                .collect::<HashSet<_>>()
                .len()
        };
        let output = HashOutput {
            files: results,
            metadata: HashMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                algorithms: algorithms.to_vec(),
                file_count,
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
                    .or_default()
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
