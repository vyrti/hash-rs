use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crossbeam_channel::{bounded, Sender};
use jwalk::WalkDir;
use rayon::prelude::*;

use crate::database::{DatabaseFormat, DatabaseHandler};
use crate::error::HashUtilityError;
use crate::hash::HashComputer;
use crate::ignore_handler::IgnoreHandler;
use crate::operation::{LegacyProgress as ProgressBar, LegacyProgressStyle as ProgressStyle};
use crate::path_utils;

/// Parallel scan implementation using producer-consumer pattern with jwalk and crossbeam-channel
#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_parallel(
    format: DatabaseFormat,
    fast_mode: bool,
    use_ignore: bool,
    algorithm: &str,
    output: &Path,
    canonical_root: &Path,
    output_absolute: &Path,
    excluded_output: Option<&Path>,
    start_time: Instant,
) -> Result<super::ScanStats, super::ScanError> {
    // Thread-safe counters for progress tracking
    let files_processed = Arc::new(Mutex::new(0usize));
    let files_failed = Arc::new(Mutex::new(0usize));
    let files_skipped = Arc::new(Mutex::new(0usize));
    let total_bytes = Arc::new(Mutex::new(0u64));

    // Create progress bar (we'll update the style once discovery is complete)
    let pb = ProgressBar::new(0);
    // Start with "Counting..." style
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] Counting... {pos} files found | Processing: {msg}")
            .unwrap()
            .progress_chars("=>-"),
    );

    // Create bounded channel with backpressure (buffer size: 10000 entries)
    let (sender, receiver) = bounded::<PathBuf>(10000);

    // Track total files discovered
    let total_files_discovered = Arc::new(Mutex::new(0usize));
    let discovery_complete = Arc::new(Mutex::new(false));

    // Clone canonical_root and output_absolute for the walker thread
    let walker_root = canonical_root.to_path_buf();
    let output_to_exclude = output_absolute.to_path_buf();
    let additional_output_to_exclude = excluded_output.map(Path::to_path_buf);

    // Clone for walker thread
    let total_files_discovered_walker = Arc::clone(&total_files_discovered);
    let discovery_complete_walker = Arc::clone(&discovery_complete);
    let pb_walker = pb.clone();

    // Spawn walker thread using jwalk to traverse directories
    let walker_handle = thread::spawn(move || {
        let result = walk_directory_streaming(
            &walker_root,
            sender,
            use_ignore,
            Some(&output_to_exclude),
            additional_output_to_exclude.as_deref(),
            Arc::clone(&total_files_discovered_walker),
        );

        // Mark discovery as complete and update progress bar with total and new style
        let total = *total_files_discovered_walker.lock().unwrap();
        pb_walker.set_length(total as u64);
        pb_walker.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({percent}%) | Processed: {msg}")
                .unwrap()
                .progress_chars("=>-")
        );
        *discovery_complete_walker.lock().unwrap() = true;

        result
    });

    // Clone Arc references for use in parallel closure
    let files_processed_clone = Arc::clone(&files_processed);
    let files_failed_clone = Arc::clone(&files_failed);
    let files_skipped_clone = Arc::clone(&files_skipped);
    let total_bytes_clone = Arc::clone(&total_bytes);
    let pb_clone = pb.clone();
    let canonical_root_clone = canonical_root.to_path_buf();

    // Use rayon's par_bridge to consume from channel in parallel
    // This starts hashing immediately as files are discovered
    let results: Vec<_> = receiver
        .into_iter()
        .par_bridge()
        .filter_map(|file_path| {
            // Check if file still exists and is accessible before processing
            let metadata_check = fs::metadata(&file_path);
            if metadata_check.is_err() {
                let mut skipped = files_skipped_clone.lock().unwrap();
                *skipped += 1;
                pb_clone.inc(1);
                return None;
            }

            // Update progress bar with counts instead of filename to avoid encoding issues
            let processed = files_processed_clone.lock().unwrap();
            let failed = files_failed_clone.lock().unwrap();
            let skipped = files_skipped_clone.lock().unwrap();
            pb_clone.set_message(format!(
                "{} OK, {} failed, {} skipped",
                *processed, *failed, *skipped
            ));
            drop(processed);
            drop(failed);
            drop(skipped);

            // Compute hash for the file (using fast mode if enabled)
            let computer = HashComputer::new();
            let hash_result = if fast_mode {
                computer.compute_hash_fast(&file_path, algorithm)
            } else {
                computer.compute_hash(&file_path, algorithm)
            };

            let result = match hash_result {
                Ok(result) => {
                    // Try to get relative path for cleaner database entries
                    // Use cached version since canonical_root_clone is already canonicalized
                    let path_to_write = match path_utils::get_relative_path_cached(
                        &file_path,
                        &canonical_root_clone,
                    ) {
                        Ok(rel_path) => rel_path,
                        Err(_) => file_path.clone(),
                    };

                    // Preserve the size before replacing the absolute path
                    // with its manifest-relative representation.
                    let file_size = fs::metadata(&file_path)
                        .map(|metadata| metadata.len())
                        .unwrap_or(0);
                    if file_size > 0 {
                        let mut bytes = total_bytes_clone.lock().unwrap();
                        *bytes += file_size;
                    }

                    // Update success counter
                    let mut processed = files_processed_clone.lock().unwrap();
                    *processed += 1;

                    Some((result.hash, path_to_write, file_size))
                }
                Err(e) => {
                    // Log error but continue processing
                    eprintln!("Warning: Failed to hash {}: {}", file_path.display(), e);

                    // Update failure counter
                    let mut failed = files_failed_clone.lock().unwrap();
                    *failed += 1;

                    None
                }
            };

            pb_clone.inc(1);
            result
        })
        .collect();

    // Wait for walker thread to complete
    match walker_handle.join() {
        Ok(walk_result) => {
            if let Err(e) = walk_result {
                eprintln!("Warning: Walker thread encountered error: {}", e);
            }
        }
        Err(e) => {
            eprintln!("Warning: Walker thread panicked: {:?}", e);
        }
    }

    let duration = start_time.elapsed();

    // Clear progress bar
    pb.finish_and_clear();

    // Write all results to output file
    let output_file = File::create(output).map_err(|e| {
        HashUtilityError::from_io_error(e, "creating output file", Some(output.to_path_buf()))
    })?;
    let mut writer = BufWriter::new(output_file);

    // Write hashdeep header if using hashdeep format
    if format == DatabaseFormat::Hashdeep {
        if let Err(e) =
            DatabaseHandler::write_hashdeep_header(&mut writer, &[algorithm.to_string()])
        {
            eprintln!("Warning: Failed to write hashdeep header: {}", e);
        }
    }

    for result in results.iter() {
        let write_result = match format {
            DatabaseFormat::Quichash => DatabaseHandler::write_entry(
                &mut writer,
                &result.0,
                algorithm,
                fast_mode,
                &result.1,
            ),
            DatabaseFormat::Hashdeep => DatabaseHandler::write_hashdeep_entry(
                &mut writer,
                result.2,
                std::slice::from_ref(&result.0),
                &result.1,
            ),
        };

        if let Err(e) = write_result {
            eprintln!("Warning: Failed to write entry: {}", e);
        }
    }

    // Flush the writer to ensure all data is written
    writer.flush().map_err(|e| {
        HashUtilityError::from_io_error(e, "flushing output file", Some(output.to_path_buf()))
    })?;

    // Extract final statistics
    let final_processed = *files_processed.lock().unwrap();
    let final_failed = *files_failed.lock().unwrap();
    let final_skipped = *files_skipped.lock().unwrap();
    let final_bytes = *total_bytes.lock().unwrap();

    // Display summary
    println!("\nScan complete!");
    println!("Files processed: {}", final_processed);
    println!("Files failed: {}", final_failed);
    println!("Files skipped: {}", final_skipped);
    println!(
        "Total bytes: {} ({:.2} MB)",
        final_bytes,
        final_bytes as f64 / 1_048_576.0
    );
    println!("Duration: {:.2}s", duration.as_secs_f64());

    // Calculate and display throughput
    if duration.as_secs_f64() > 0.0 {
        let throughput_mbps = (final_bytes as f64 / 1_048_576.0) / duration.as_secs_f64();
        println!("Throughput: {:.2} MB/s", throughput_mbps);
    }

    println!("Output written to: {}", output.display());

    Ok(super::ScanStats {
        files_processed: final_processed,
        files_failed: final_failed + final_skipped,
        total_bytes: final_bytes,
        duration,
    })
}

/// Walk directory using jwalk and send file paths to channel as they're discovered
pub(crate) fn walk_directory_streaming(
    root: &Path,
    sender: Sender<PathBuf>,
    use_ignore: bool,
    exclude_file: Option<&Path>,
    additional_exclude_file: Option<&Path>,
    total_files_discovered: Arc<Mutex<usize>>,
) -> Result<(), super::ScanError> {
    // Load .hashignore patterns if enabled
    let ignore_handler = if use_ignore {
        match IgnoreHandler::new(root) {
            Ok(handler) => Some(Arc::new(handler)),
            Err(e) => {
                eprintln!("Warning: Failed to load .hashignore: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Canonicalize exclude path once before the loop to avoid redundant calls
    let canonical_exclude = exclude_file.and_then(|p| p.canonicalize().ok());
    let canonical_additional_exclude = additional_exclude_file.and_then(|p| p.canonicalize().ok());

    // Prune ignored directories before traversal so directory-only patterns
    // also exclude every descendant in the parallel walker.
    let mut walker = WalkDir::new(root)
        .parallelism(jwalk::Parallelism::RayonNewPool(0)) // 0 = use default thread count
        .skip_hidden(false) // Don't skip hidden files
        .follow_links(false);
    if let Some(handler) = ignore_handler.clone() {
        let root = root.to_path_buf();
        walker = walker.process_read_dir(move |_depth, _dir, _state, children| {
            for child_result in children.iter_mut() {
                let Ok(child) = child_result else {
                    continue;
                };
                if !child.file_type.is_dir() {
                    continue;
                }
                let child_path = child.path();
                if child_path
                    .strip_prefix(&root)
                    .is_ok_and(|relative| handler.should_ignore(relative, true))
                {
                    child.read_children = None;
                }
            }
        });
    }

    for entry_result in walker {
        match entry_result {
            Ok(entry) => {
                let path = entry.path();

                // Only process regular files
                if !entry.file_type().is_file() {
                    continue;
                }

                // Check if this is the excluded file
                if let Some(ref exclude_canonical) = canonical_exclude {
                    // Compare canonical paths (only canonicalize current path once)
                    if let Ok(canonical_path) = path.canonicalize() {
                        if &canonical_path == exclude_canonical {
                            continue;
                        }
                    }
                }
                if let Some(ref exclude_canonical) = canonical_additional_exclude {
                    if let Ok(canonical_path) = path.canonicalize() {
                        if &canonical_path == exclude_canonical {
                            continue;
                        }
                    }
                }

                // Check if this path should be ignored
                if let Some(ref handler) = ignore_handler {
                    if let Ok(rel_path) = path.strip_prefix(root) {
                        if handler.should_ignore(rel_path, false) {
                            continue;
                        }
                    }
                }

                // Send file path to channel
                // If channel is full, this will block (backpressure)
                if sender.send(path).is_err() {
                    // Receiver has been dropped, stop walking
                    break;
                }

                // Track total files discovered
                let mut total = total_files_discovered.lock().unwrap();
                *total += 1;
            }
            Err(e) => {
                // Log errors during directory scans without stopping
                eprintln!("Warning: Error walking directory: {}", e);
            }
        }
    }

    Ok(())
}
