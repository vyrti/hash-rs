use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crossbeam_channel::{Sender, bounded};
use jwalk::WalkDir;
use rayon::prelude::*;

use crate::database::{DatabaseFormat, DatabaseHandler};
use crate::error::HashUtilityError;
use crate::hash::HashComputer;
use crate::ignore_handler::IgnoreHandler;
use crate::operation::{LegacyProgress as ProgressBar, LegacyProgressStyle as ProgressStyle};

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
    let files_processed = Arc::new(AtomicUsize::new(0));
    let files_failed = Arc::new(AtomicUsize::new(0));
    let files_skipped = Arc::new(AtomicUsize::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));

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
    let (result_sender, result_receiver) = bounded::<(String, PathBuf, u64)>(10000);
    let writer_output = output.to_owned();
    let writer_algorithm = algorithm.to_owned();
    let writer_handle = thread::spawn(move || -> Result<(), HashUtilityError> {
        let output_file = File::create(&writer_output).map_err(|error| {
            HashUtilityError::from_io_error(
                error,
                "creating output file",
                Some(writer_output.clone()),
            )
        })?;
        let mut writer = BufWriter::new(output_file);
        if format == DatabaseFormat::Hashdeep {
            DatabaseHandler::write_hashdeep_header(
                &mut writer,
                std::slice::from_ref(&writer_algorithm),
            )?;
        }
        for (hash, path, size) in result_receiver {
            match format {
                DatabaseFormat::Quichash => DatabaseHandler::write_entry(
                    &mut writer,
                    &hash,
                    &writer_algorithm,
                    fast_mode,
                    &path,
                )?,
                DatabaseFormat::Hashdeep => DatabaseHandler::write_hashdeep_entry(
                    &mut writer,
                    size,
                    std::slice::from_ref(&hash),
                    &path,
                )?,
            }
        }
        writer.flush().map_err(|error| {
            HashUtilityError::from_io_error(error, "flushing output file", Some(writer_output))
        })
    });

    // Track total files discovered
    let total_files_discovered = Arc::new(Mutex::new(0usize));

    // Clone canonical_root and output_absolute for the walker thread
    let walker_root = canonical_root.to_path_buf();
    let output_to_exclude = output_absolute.to_path_buf();
    let additional_output_to_exclude = excluded_output.map(Path::to_path_buf);

    // Clone for walker thread
    let total_files_discovered_walker = Arc::clone(&total_files_discovered);
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
    receiver
        .into_iter()
        .par_bridge()
        .map_init(
            || (HashComputer::new(), vec![0_u8; 1024 * 1024]),
            |(computer, buffer), file_path| {
                // Check if file still exists and is accessible before processing
                let metadata = match fs::metadata(&file_path) {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        files_skipped_clone.fetch_add(1, Ordering::Relaxed);
                        pb_clone.inc(1);
                        return None;
                    }
                };
                let file_size = metadata.len();

                // Compute hash for the file (using fast mode if enabled)
                let hash_result = computer
                    .compute_hash_for_worker(&file_path, algorithm, fast_mode, file_size, buffer);

                let result = match hash_result {
                    Ok(result) => {
                        // Try to get relative path for cleaner database entries
                        // Use cached version since canonical_root_clone is already canonicalized
                        let path_to_write = file_path
                            .strip_prefix(&canonical_root_clone)
                            .map(Path::to_path_buf)
                            .unwrap_or_else(|_| file_path.clone());

                        // Preserve the size before replacing the absolute path
                        // with its manifest-relative representation.
                        if file_size > 0 {
                            total_bytes_clone.fetch_add(file_size, Ordering::Relaxed);
                        }

                        // Update success counter
                        files_processed_clone.fetch_add(1, Ordering::Relaxed);

                        Some((result.hash, path_to_write, file_size))
                    }
                    Err(e) => {
                        // Log error but continue processing
                        eprintln!("Warning: Failed to hash {}: {}", file_path.display(), e);

                        // Update failure counter
                        files_failed_clone.fetch_add(1, Ordering::Relaxed);

                        None
                    }
                };

                pb_clone.inc(1);
                result
            },
        )
        .for_each(|result| {
            if let Some(result) = result {
                let _ = result_sender.send(result);
            }
        });
    drop(result_sender);

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

    match writer_handle.join() {
        Ok(result) => result?,
        Err(panic) => {
            return Err(HashUtilityError::HashComputationFailed {
                path: output.to_owned(),
                algorithm: algorithm.to_owned(),
                reason: format!("database writer thread panicked: {panic:?}"),
            });
        }
    }

    let duration = start_time.elapsed();

    // Clear progress bar
    pb.finish_and_clear();

    // Extract final statistics
    let final_processed = files_processed.load(Ordering::Relaxed);
    let final_failed = files_failed.load(Ordering::Relaxed);
    let final_skipped = files_skipped.load(Ordering::Relaxed);
    let final_bytes = total_bytes.load(Ordering::Relaxed);

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
        // Discovery overlaps the global Rayon hashing pool. A small dedicated
        // walker pool avoids doubling the runnable thread count.
        .parallelism(jwalk::Parallelism::RayonNewPool(2))
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

    let mut discovered = 0_usize;
    for entry_result in walker {
        match entry_result {
            Ok(entry) => {
                let path = entry.path();

                // Only process regular files
                if !entry.file_type().is_file() {
                    continue;
                }

                // Check if this is the excluded file
                if exclude_file.is_some_and(|excluded| path == excluded)
                    || canonical_exclude
                        .as_ref()
                        .is_some_and(|excluded| path == *excluded)
                {
                    continue;
                }
                if additional_exclude_file.is_some_and(|excluded| path == excluded)
                    || canonical_additional_exclude
                        .as_ref()
                        .is_some_and(|excluded| path == *excluded)
                {
                    continue;
                }

                // Check if this path should be ignored
                if let Some(ref handler) = ignore_handler
                    && let Ok(rel_path) = path.strip_prefix(root)
                    && handler.should_ignore(rel_path, false)
                {
                    continue;
                }

                // Send file path to channel
                // If channel is full, this will block (backpressure)
                if sender.send(path).is_err() {
                    // Receiver has been dropped, stop walking
                    break;
                }

                // Track total files discovered
                discovered += 1;
            }
            Err(e) => {
                // Log errors during directory scans without stopping
                eprintln!("Warning: Error walking directory: {}", e);
            }
        }
    }

    *total_files_discovered.lock().unwrap() += discovered;

    Ok(())
}
