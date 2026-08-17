use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crossbeam_channel::bounded;
use jwalk::WalkDir;
use rayon::prelude::*;

use crate::error::HashUtilityError;
use crate::hash::HashComputer;
use crate::ignore_handler::IgnoreHandler;
use crate::operation::{LegacyProgress as ProgressBar, LegacyProgressStyle as ProgressStyle};

type DedupScanResult =
    Result<(HashMap<String, Vec<(PathBuf, u64)>>, usize, usize, u64), HashUtilityError>;

/// Sequential scan implementation
pub(crate) fn scan_sequential(
    computer: &HashComputer,
    fast_mode: bool,
    canonical_root: &Path,
    _start_time: Instant,
) -> DedupScanResult {
    // Collect all files
    let files = collect_files(canonical_root)?;

    println!("Found {} files to process", files.len());

    // Track statistics
    let mut files_scanned = 0;
    let mut files_failed = 0;
    let mut total_bytes = 0u64;

    // Map from hash to list of (path, size) tuples
    let mut hash_map: HashMap<String, Vec<(PathBuf, u64)>> = HashMap::new();

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
        // Update progress bar
        pb.set_message(format!("{} OK, {} failed", files_scanned, files_failed));

        // Check if file still exists and is accessible
        let metadata = match fs::metadata(file_path) {
            Ok(m) => m,
            Err(_) => {
                files_failed += 1;
                pb.inc(1);
                continue;
            }
        };

        let file_size = metadata.len();

        // Compute hash for the file (always use BLAKE3)
        let hash_result = if fast_mode {
            computer.compute_hash_fast(file_path, "blake3")
        } else {
            computer.compute_hash(file_path, "blake3")
        };

        match hash_result {
            Ok(result) => {
                // Add to hash map
                hash_map
                    .entry(result.hash)
                    .or_default()
                    .push((file_path.clone(), file_size));

                files_scanned += 1;
                total_bytes += file_size;
            }
            Err(e) => {
                eprintln!("Warning: Failed to hash {}: {}", file_path.display(), e);
                files_failed += 1;
            }
        }

        pb.inc(1);
    }

    pb.finish_and_clear();

    Ok((hash_map, files_scanned, files_failed, total_bytes))
}

/// Parallel scan implementation using producer-consumer pattern
pub(crate) fn scan_parallel(
    fast_mode: bool,
    canonical_root: &Path,
    _start_time: Instant,
) -> DedupScanResult {
    // Thread-safe counters
    let files_scanned = Arc::new(Mutex::new(0usize));
    let files_failed = Arc::new(Mutex::new(0usize));
    let total_bytes = Arc::new(Mutex::new(0u64));

    // Create progress bar
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] Counting... {pos} files found | Processing: {msg}")
            .unwrap()
            .progress_chars("=>-"),
    );

    // Create bounded channel
    let (sender, receiver) = bounded::<PathBuf>(10000);

    // Track total files discovered
    let total_files_discovered = Arc::new(Mutex::new(0usize));
    let discovery_complete = Arc::new(Mutex::new(false));

    // Clone for walker thread
    let walker_root = canonical_root.to_path_buf();
    let total_files_discovered_walker = Arc::clone(&total_files_discovered);
    let discovery_complete_walker = Arc::clone(&discovery_complete);
    let pb_walker = pb.clone();

    // Spawn walker thread
    let walker_handle = thread::spawn(move || {
        let result = walk_directory_streaming(
            &walker_root,
            sender,
            Arc::clone(&total_files_discovered_walker),
        );

        // Mark discovery as complete
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

    // Clone Arc references for parallel closure
    let files_scanned_clone = Arc::clone(&files_scanned);
    let files_failed_clone = Arc::clone(&files_failed);
    let total_bytes_clone = Arc::clone(&total_bytes);
    let pb_clone = pb.clone();

    // Use rayon's par_bridge to consume from channel in parallel
    let results: Vec<_> = receiver
        .into_iter()
        .par_bridge()
        .filter_map(|file_path| {
            // Check if file still exists and is accessible
            let metadata = match fs::metadata(&file_path) {
                Ok(m) => m,
                Err(_) => {
                    let mut failed = files_failed_clone.lock().unwrap();
                    *failed += 1;
                    pb_clone.inc(1);
                    return None;
                }
            };

            let file_size = metadata.len();

            // Update progress bar
            let scanned = files_scanned_clone.lock().unwrap();
            let failed = files_failed_clone.lock().unwrap();
            pb_clone.set_message(format!("{} OK, {} failed", *scanned, *failed));
            drop(scanned);
            drop(failed);

            // Compute hash (always use BLAKE3)
            let computer = HashComputer::new();
            let hash_result = if fast_mode {
                computer.compute_hash_fast(&file_path, "blake3")
            } else {
                computer.compute_hash(&file_path, "blake3")
            };

            let result = match hash_result {
                Ok(result) => {
                    // Update counters
                    let mut scanned = files_scanned_clone.lock().unwrap();
                    *scanned += 1;
                    let mut bytes = total_bytes_clone.lock().unwrap();
                    *bytes += file_size;

                    Some((result.hash, file_path.clone(), file_size))
                }
                Err(e) => {
                    eprintln!("Warning: Failed to hash {}: {}", file_path.display(), e);
                    let mut failed = files_failed_clone.lock().unwrap();
                    *failed += 1;
                    None
                }
            };

            pb_clone.inc(1);
            result
        })
        .collect();

    // Wait for walker thread
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

    pb.finish_and_clear();

    // Build hash map from results
    let mut hash_map: HashMap<String, Vec<(PathBuf, u64)>> = HashMap::new();
    for (hash, path, size) in results {
        hash_map.entry(hash).or_default().push((path, size));
    }

    // Extract final statistics
    let final_scanned = *files_scanned.lock().unwrap();
    let final_failed = *files_failed.lock().unwrap();
    let final_bytes = *total_bytes.lock().unwrap();

    Ok((hash_map, final_scanned, final_failed, final_bytes))
}

/// Walk directory and send file paths to channel
pub(crate) fn walk_directory_streaming(
    root: &Path,
    sender: crossbeam_channel::Sender<PathBuf>,
    total_files_discovered: Arc<Mutex<usize>>,
) -> Result<(), HashUtilityError> {
    // Load .hashignore patterns
    let ignore_handler = match IgnoreHandler::new(root) {
        Ok(handler) => Some(Arc::new(handler)),
        Err(e) => {
            eprintln!("Warning: Failed to load .hashignore: {}", e);
            None
        }
    };

    let mut walker = WalkDir::new(root)
        .parallelism(jwalk::Parallelism::RayonNewPool(0))
        .skip_hidden(false)
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
                    child.read_children_path = None;
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

                // Check if this path should be ignored
                if let Some(ref handler) = ignore_handler {
                    if let Ok(rel_path) = path.strip_prefix(root) {
                        if handler.should_ignore(rel_path, false) {
                            continue;
                        }
                    }
                }

                // Send file path to channel
                if sender.send(path).is_err() {
                    break;
                }

                // Track total files discovered
                let mut total = total_files_discovered.lock().unwrap();
                *total += 1;
            }
            Err(e) => {
                eprintln!("Warning: Error walking directory: {}", e);
            }
        }
    }

    Ok(())
}

/// Recursively collect all regular files in a directory tree
pub(crate) fn collect_files(root: &Path) -> Result<Vec<PathBuf>, HashUtilityError> {
    let mut files = Vec::new();

    // Load .hashignore patterns
    let ignore_handler = match IgnoreHandler::new(root) {
        Ok(handler) => Some(handler),
        Err(e) => {
            eprintln!("Warning: Failed to load .hashignore: {}", e);
            None
        }
    };

    collect_files_recursive(root, root, &mut files, ignore_handler.as_ref())?;
    Ok(files)
}

/// Helper function for recursive file collection
pub(crate) fn collect_files_recursive(
    root: &Path,
    dir: &Path,
    files: &mut Vec<PathBuf>,
    ignore_handler: Option<&IgnoreHandler>,
) -> Result<(), HashUtilityError> {
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

        // Get metadata
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

        // Check if this path should be ignored
        if let Some(handler) = ignore_handler {
            if let Ok(rel_path) = path.strip_prefix(root) {
                if handler.should_ignore(rel_path, is_dir) {
                    continue;
                }
            }
        }

        if metadata.is_file() {
            files.push(path);
        } else if is_dir {
            if let Err(e) = collect_files_recursive(root, &path, files, ignore_handler) {
                eprintln!(
                    "Warning: Error processing directory {}: {}",
                    path.display(),
                    e
                );
            }
        }
    }

    Ok(())
}
