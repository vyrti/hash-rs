use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rayon::prelude::*;

use super::report::{Mismatch, VerifyReport};
use crate::database::DatabaseEntry;
use crate::error::HashUtilityError;
use crate::hash::HashComputer;
use crate::operation::{LegacyProgress as ProgressBar, LegacyProgressStyle as ProgressStyle};
use crate::path_utils;

/// Backward-compatible error name for verification operations.
pub type VerifyError = HashUtilityError;

/// Sequential verification implementation
pub(crate) fn verify_sequential(
    computer: &HashComputer,
    database_canonical: HashMap<PathBuf, DatabaseEntry>,
    current_files: HashSet<PathBuf>,
) -> Result<VerifyReport, VerifyError> {
    // Track results
    let mut matches = 0;
    let mut mismatches = Vec::new();
    let mut missing_files = Vec::new();
    let mut checked_files = HashSet::new();

    // Create progress bar
    let pb = ProgressBar::new(database_canonical.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({percent}%) | {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
    );

    // Check each file in the database
    for (db_path, entry) in &database_canonical {
        checked_files.insert(db_path.clone());

        // Update progress bar with current file
        let file_name = db_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        pb.set_message(format!("Verifying: {}", file_name));

        if current_files.contains(db_path) {
            // File exists, compute current hash using the mode specified in the database
            let hash_result = if entry.fast_mode {
                computer.compute_hash_fast(db_path, &entry.algorithm)
            } else {
                computer.compute_hash(db_path, &entry.algorithm)
            };

            match hash_result {
                Ok(result) => {
                    if result.hash == entry.hash {
                        matches += 1;
                    } else {
                        mismatches.push(Mismatch {
                            path: db_path.clone(),
                            expected: entry.hash.clone(),
                            actual: result.hash,
                        });
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to hash {}: {}", db_path.display(), e);
                }
            }
        } else {
            // File in database but not in filesystem
            missing_files.push(db_path.clone());
        }

        pb.inc(1);
    }

    // Clear progress bar
    pb.finish_and_clear();

    // Find new files (in filesystem but not in database)
    let new_files: Vec<PathBuf> = current_files
        .iter()
        .filter(|path| !checked_files.contains(*path))
        .cloned()
        .collect();

    Ok(VerifyReport {
        matches,
        mismatches,
        missing_files,
        new_files,
    })
}

/// Parallel verification implementation using rayon
pub(crate) fn verify_parallel(
    database_canonical: HashMap<PathBuf, DatabaseEntry>,
    current_files: HashSet<PathBuf>,
) -> Result<VerifyReport, VerifyError> {
    // Thread-safe counters for progress tracking
    let matches = Arc::new(Mutex::new(0usize));
    let mismatches = Arc::new(Mutex::new(Vec::new()));
    let missing_files = Arc::new(Mutex::new(Vec::new()));

    // Create progress bar
    let pb = ProgressBar::new(database_canonical.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({percent}%) | {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
    );

    // Clone Arc references for use in parallel closure
    let matches_clone = Arc::clone(&matches);
    let mismatches_clone = Arc::clone(&mismatches);
    let missing_files_clone = Arc::clone(&missing_files);
    let pb_clone = pb.clone();

    // Collect database entries into a vector for parallel iteration
    let db_entries: Vec<_> = database_canonical.iter().collect();

    // Process all database entries in parallel
    let checked_files: Vec<PathBuf> = db_entries
        .par_iter()
        .map(|(db_path, entry)| {
            // Update progress bar
            let match_count = *matches_clone.lock().unwrap();
            let mismatch_count = mismatches_clone.lock().unwrap().len();
            let missing_count = missing_files_clone.lock().unwrap().len();
            pb_clone.set_message(format!(
                "{} OK, {} changed, {} missing",
                match_count, mismatch_count, missing_count
            ));

            if current_files.contains(*db_path) {
                // File exists, compute current hash using the mode specified in the database
                let computer = HashComputer::new();
                let hash_result = if entry.fast_mode {
                    computer.compute_hash_fast(db_path, &entry.algorithm)
                } else {
                    computer.compute_hash(db_path, &entry.algorithm)
                };

                match hash_result {
                    Ok(result) => {
                        if result.hash == entry.hash {
                            let mut count = matches_clone.lock().unwrap();
                            *count += 1;
                        } else {
                            let mut list = mismatches_clone.lock().unwrap();
                            list.push(Mismatch {
                                path: (*db_path).clone(),
                                expected: entry.hash.clone(),
                                actual: result.hash,
                            });
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to hash {}: {}", db_path.display(), e);
                    }
                }
            } else {
                // File in database but not in filesystem
                let mut list = missing_files_clone.lock().unwrap();
                list.push((*db_path).clone());
            }

            pb_clone.inc(1);
            (*db_path).clone()
        })
        .collect();

    // Clear progress bar
    pb.finish_and_clear();

    // Convert checked_files to HashSet for efficient lookup
    let checked_set: HashSet<PathBuf> = checked_files.into_iter().collect();

    // Find new files (in filesystem but not in database)
    let new_files: Vec<PathBuf> = current_files
        .iter()
        .filter(|path| !checked_set.contains(*path))
        .cloned()
        .collect();

    // Extract final results from Arc<Mutex<>>
    let final_matches = *matches.lock().unwrap();
    let final_mismatches = mismatches.lock().unwrap().clone();
    let final_missing = missing_files.lock().unwrap().clone();

    Ok(VerifyReport {
        matches: final_matches,
        mismatches: final_mismatches,
        missing_files: final_missing,
        new_files,
    })
}

/// Optimized file collection using jwalk (same as scan)
pub(crate) fn collect_files_optimized(directory: &Path) -> Result<HashSet<PathBuf>, VerifyError> {
    use jwalk::WalkDir;

    let mut files = HashSet::new();

    // Use jwalk for fast parallel directory traversal (same configuration as scan)
    for entry_result in WalkDir::new(directory)
        .parallelism(jwalk::Parallelism::RayonNewPool(0))
        .skip_hidden(false) // Don't skip hidden files
        .follow_links(false)
    // Don't follow symlinks to avoid loops
    {
        match entry_result {
            Ok(entry) => {
                // Only process regular files
                if !entry.file_type().is_file() {
                    continue;
                }

                let path = entry.path();

                // Canonicalize the path for consistent comparison
                if let Ok(canonical_path) = path.canonicalize() {
                    files.insert(canonical_path);
                }
            }
            Err(e) => {
                // Log errors but continue processing
                eprintln!("Warning: Error walking directory: {}", e);
            }
        }
    }

    Ok(files)
}

/// Optimized path resolution with caching to reduce canonicalization overhead
pub(crate) fn resolve_database_paths_optimized(
    database: &HashMap<PathBuf, DatabaseEntry>,
    base_directory: &Path,
) -> Result<HashMap<PathBuf, DatabaseEntry>, VerifyError> {
    let mut resolved = HashMap::new();
    let mut canonical_cache: HashMap<PathBuf, PathBuf> = HashMap::new();

    for (path, entry) in database {
        // Use path_utils to resolve the path properly
        let absolute_path = path_utils::resolve_path(path, base_directory);

        // Check cache first to avoid redundant canonicalization
        let final_path = if let Some(cached) = canonical_cache.get(&absolute_path) {
            cached.clone()
        } else {
            // Try to canonicalize if the file exists, otherwise use as-is
            let result = match path_utils::try_canonicalize(&absolute_path) {
                Ok(canonical) => canonical,
                Err(_) => absolute_path.clone(),
            };
            canonical_cache.insert(absolute_path, result.clone());
            result
        };

        resolved.insert(final_path, entry.clone());
    }

    Ok(resolved)
}
