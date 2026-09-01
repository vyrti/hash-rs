use std::collections::HashMap;
use std::fs::{self, File};
use std::hash::{DefaultHasher, Hasher as _};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use jwalk::WalkDir;
use rayon::prelude::*;

use crate::error::HashUtilityError;
use crate::hash::HashComputer;
use crate::ignore_handler::IgnoreHandler;

type DedupScanResult =
    Result<(HashMap<String, Vec<(PathBuf, u64)>>, usize, usize, u64), HashUtilityError>;

/// Sequential scan implementation
pub(crate) fn scan_sequential(
    computer: &HashComputer,
    fast_mode: bool,
    canonical_root: &Path,
    _start_time: Instant,
) -> DedupScanResult {
    let files = collect_files(canonical_root)?;
    println!("Found {} files to process", files.len());
    hash_duplicate_candidates(computer, fast_mode, files, false)
}

/// Parallel scan implementation using producer-consumer pattern
pub(crate) fn scan_parallel(
    fast_mode: bool,
    canonical_root: &Path,
    _start_time: Instant,
) -> DedupScanResult {
    let files = collect_files_jwalk(canonical_root)?;
    println!("Found {} files to process", files.len());
    hash_duplicate_candidates(&HashComputer::new(), fast_mode, files, true)
}

fn hash_duplicate_candidates(
    computer: &HashComputer,
    fast_mode: bool,
    files: Vec<PathBuf>,
    parallel: bool,
) -> DedupScanResult {
    let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    let mut files_failed = 0;
    let mut files_scanned = 0;
    let mut total_bytes = 0_u64;
    for path in files {
        match fs::metadata(&path) {
            Ok(metadata) => {
                let size = metadata.len();
                by_size.entry(size).or_default().push(path);
                files_scanned += 1;
                total_bytes += size;
            }
            Err(_) => files_failed += 1,
        }
    }

    let same_size: Vec<_> = by_size
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .flat_map(|(size, paths)| paths.into_iter().map(move |path| (path, size)))
        .collect();
    let signatures: Vec<_> = if parallel {
        same_size
            .par_iter()
            .map_init(
                || vec![0_u8; 64 * 1024],
                |buffer, (path, size)| {
                    prefix_signature(path, buffer).map(|signature| (path.clone(), *size, signature))
                },
            )
            .collect()
    } else {
        let mut buffer = vec![0_u8; 64 * 1024];
        same_size
            .iter()
            .map(|(path, size)| {
                prefix_signature(path, &mut buffer)
                    .map(|signature| (path.clone(), *size, signature))
            })
            .collect()
    };

    let mut by_prefix: HashMap<(u64, u64), Vec<PathBuf>> = HashMap::new();
    for result in signatures {
        match result {
            Ok((path, size, signature)) => {
                by_prefix.entry((size, signature)).or_default().push(path);
            }
            Err(_) => files_failed += 1,
        }
    }
    let candidates: Vec<_> = by_prefix
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .flat_map(|((size, _), paths)| paths.into_iter().map(move |path| (path, size)))
        .collect();

    let hashes: Vec<_> = if parallel {
        candidates
            .par_iter()
            .map_init(
                || (HashComputer::new(), vec![0_u8; 1024 * 1024]),
                |(computer, buffer), (path, size)| {
                    computer
                        .compute_hash_for_worker(path, "blake3", fast_mode, *size, buffer)
                        .map(|result| (result.hash, path.clone(), *size))
                },
            )
            .collect()
    } else {
        let mut buffer = vec![0_u8; computer.buffer_size()];
        candidates
            .iter()
            .map(|(path, size)| {
                computer
                    .compute_hash_for_worker(path, "blake3", fast_mode, *size, &mut buffer)
                    .map(|result| (result.hash, path.clone(), *size))
            })
            .collect()
    };

    let mut hash_map: HashMap<String, Vec<(PathBuf, u64)>> = HashMap::new();
    for result in hashes {
        match result {
            Ok((hash, path, size)) => hash_map.entry(hash).or_default().push((path, size)),
            Err(error) => {
                eprintln!("Warning: Failed to hash duplicate candidate: {error}");
                files_failed += 1;
            }
        }
    }
    Ok((hash_map, files_scanned, files_failed, total_bytes))
}

fn prefix_signature(path: &Path, buffer: &mut [u8]) -> std::io::Result<u64> {
    let mut file = File::open(path)?;
    let amount = file.read(buffer)?;
    let mut hasher = DefaultHasher::new();
    hasher.write(&buffer[..amount]);
    Ok(hasher.finish())
}

fn collect_files_jwalk(root: &Path) -> Result<Vec<PathBuf>, HashUtilityError> {
    let (sender, receiver) = crossbeam_channel::unbounded();
    walk_directory_streaming(root, sender, Arc::new(Mutex::new(0)))?;
    Ok(receiver.into_iter().collect())
}

/// Walk directory and send file paths to channel
pub fn walk_directory_streaming(
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

                // Check if this path should be ignored
                if let Some(ref handler) = ignore_handler
                    && let Ok(rel_path) = path.strip_prefix(root)
                    && handler.should_ignore(rel_path, false)
                {
                    continue;
                }

                // Send file path to channel
                if sender.send(path).is_err() {
                    break;
                }

                // Track total files discovered
                discovered += 1;
            }
            Err(e) => {
                eprintln!("Warning: Error walking directory: {}", e);
            }
        }
    }

    *total_files_discovered.lock().unwrap() += discovered;

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
        if let Some(handler) = ignore_handler
            && let Ok(rel_path) = path.strip_prefix(root)
            && handler.should_ignore(rel_path, is_dir)
        {
            continue;
        }

        if metadata.is_file() {
            files.push(path);
        } else if is_dir && let Err(e) = collect_files_recursive(root, &path, files, ignore_handler)
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
