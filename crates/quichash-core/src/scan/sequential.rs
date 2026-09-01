use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::database::{DatabaseFormat, DatabaseHandler};
use crate::error::HashUtilityError;
use crate::hash::HashComputer;
use crate::operation::{LegacyProgress as ProgressBar, LegacyProgressStyle as ProgressStyle};
use crate::path_utils;

/// Sequential scan implementation
#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_sequential(
    computer: &HashComputer,
    format: DatabaseFormat,
    fast_mode: bool,
    files: &[PathBuf],
    algorithm: &str,
    output: &Path,
    canonical_root: &Path,
    start_time: Instant,
) -> Result<super::ScanStats, super::ScanError> {
    // Open output file for writing
    let output_file = File::create(output).map_err(|e| {
        HashUtilityError::from_io_error(e, "creating output file", Some(output.to_path_buf()))
    })?;
    let mut writer = BufWriter::new(output_file);

    // Write hashdeep header if using hashdeep format
    if format == DatabaseFormat::Hashdeep {
        DatabaseHandler::write_hashdeep_header(&mut writer, &[algorithm.to_string()]).map_err(
            |e| {
                HashUtilityError::from_io_error(
                    e,
                    "writing hashdeep header",
                    Some(output.to_path_buf()),
                )
            },
        )?;
    }

    // Track statistics
    let mut files_processed = 0;
    let mut files_failed = 0;
    let mut files_skipped = 0;
    let mut total_bytes = 0u64;

    // Create progress bar
    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({percent}%) | Processed: {msg}")
            .unwrap()
            .progress_chars("=>-")
    );

    // Process each file
    for file_path in files.iter() {
        // Update progress bar with counts instead of filename to avoid encoding issues
        pb.set_message(format!(
            "{} OK, {} failed, {} skipped",
            files_processed, files_failed, files_skipped
        ));

        // Check if file still exists and is accessible before processing
        let metadata_check = fs::metadata(file_path);
        if metadata_check.is_err() {
            files_skipped += 1;
            pb.inc(1);
            continue;
        }

        // Compute hash for the file (using fast mode if enabled)
        let hash_result = if fast_mode {
            computer.compute_hash_fast(file_path, algorithm)
        } else {
            computer.compute_hash(file_path, algorithm)
        };

        match hash_result {
            Ok(result) => {
                // Try to get relative path for cleaner database entries
                // Use cached version since canonical_root is already canonicalized
                let path_to_write =
                    match path_utils::get_relative_path_cached(file_path, canonical_root) {
                        Ok(rel_path) => rel_path,
                        Err(_) => file_path.clone(),
                    };

                // Get file size for hashdeep format
                let file_size = fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);

                // Write hash entry to database with metadata
                let write_result = match format {
                    DatabaseFormat::Quichash => DatabaseHandler::write_entry(
                        &mut writer,
                        &result.hash,
                        algorithm,
                        fast_mode,
                        &path_to_write,
                    ),
                    DatabaseFormat::Hashdeep => DatabaseHandler::write_hashdeep_entry(
                        &mut writer,
                        file_size,
                        std::slice::from_ref(&result.hash),
                        &path_to_write,
                    ),
                };

                if let Err(e) = write_result {
                    eprintln!(
                        "Warning: Failed to write entry for {}: {}",
                        file_path.display(),
                        e
                    );
                    files_failed += 1;
                } else {
                    files_processed += 1;
                    total_bytes += file_size;
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to hash {}: {}", file_path.display(), e);
                files_failed += 1;
            }
        }

        pb.inc(1);
    }

    let duration = start_time.elapsed();

    // Clear progress bar and display summary
    pb.finish_and_clear();

    println!("\nScan complete!");
    println!("Files processed: {}", files_processed);
    println!("Files failed: {}", files_failed);
    println!("Files skipped: {}", files_skipped);
    println!(
        "Total bytes: {} ({:.2} MB)",
        total_bytes,
        total_bytes as f64 / 1_048_576.0
    );
    println!("Duration: {:.2}s", duration.as_secs_f64());

    // Calculate and display throughput
    if duration.as_secs_f64() > 0.0 {
        let throughput_mbps = (total_bytes as f64 / 1_048_576.0) / duration.as_secs_f64();
        println!("Throughput: {:.2} MB/s", throughput_mbps);
    }

    println!("Output written to: {}", output.display());

    Ok(super::ScanStats {
        files_processed,
        files_failed: files_failed + files_skipped,
        total_bytes,
        duration,
    })
}

/// Helper function to collect files with output file exclusion
pub(crate) fn collect_files_with_exclusion(
    use_ignore: bool,
    root: &Path,
    exclude_file: Option<&Path>,
) -> Result<Vec<PathBuf>, super::ScanError> {
    let mut files = Vec::new();

    // Canonicalize exclude path if provided and exists
    let canonical_exclude = exclude_file.and_then(|p| p.canonicalize().ok());

    // Load .hashignore patterns if enabled
    let ignore_handler = if use_ignore {
        match crate::ignore_handler::IgnoreHandler::new(root) {
            Ok(handler) => Some(handler),
            Err(e) => {
                eprintln!("Warning: Failed to load .hashignore: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Use cached recursive collection
    collect_files_recursive_with_cache(
        root,
        root,
        &mut files,
        ignore_handler.as_ref(),
        exclude_file,
        canonical_exclude.as_ref(),
    )?;

    Ok(files)
}

/// Cached and optimized helper function for recursive file collection
pub(crate) fn collect_files_recursive_with_cache(
    root: &Path,
    dir: &Path,
    files: &mut Vec<PathBuf>,
    ignore_handler: Option<&crate::ignore_handler::IgnoreHandler>,
    _exclude_file: Option<&Path>,
    canonical_exclude_cache: Option<&PathBuf>,
) -> Result<(), super::ScanError> {
    // Check if path exists and is accessible
    if !dir.exists() {
        return Err(HashUtilityError::DirectoryNotFound {
            path: dir.to_path_buf(),
        });
    }

    // Read directory entries
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Warning: Cannot read directory {}: {}", dir.display(), e);
            return Ok(());
        }
    };

    // Process each entry
    for entry_result in entries {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("Warning: Cannot read directory entry: {}", e);
                continue;
            }
        };

        let path = entry.path();

        // Get metadata once to avoid multiple syscalls
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(e) => {
                eprintln!(
                    "Warning: Cannot read metadata for {}: {}",
                    path.display(),
                    e
                );
                continue;
            }
        };

        let is_dir = metadata.is_dir();

        // Check if this is the excluded file using cached canonical path
        if let Some(exclude_canonical) = canonical_exclude_cache
            && let Ok(canonical_path) = path.canonicalize()
            && &canonical_path == exclude_canonical
        {
            continue;
        }

        // Check if this path should be ignored
        if let Some(handler) = ignore_handler
            && let Ok(rel_path) = path.strip_prefix(root)
            && handler.should_ignore(rel_path, is_dir)
        {
            continue;
        }

        if metadata.is_file() {
            files.push(path);
        } else if is_dir
            && let Err(e) = collect_files_recursive_with_cache(
                root,
                &path,
                files,
                ignore_handler,
                _exclude_file,
                canonical_exclude_cache,
            )
        {
            eprintln!(
                "Warning: Error processing directory {}: {}",
                path.display(),
                e
            );
        }
    }

    Ok(())
}
