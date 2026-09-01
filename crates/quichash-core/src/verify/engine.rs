use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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

    enum Outcome {
        Match,
        Mismatch(Mismatch),
        Missing(PathBuf),
        Failed,
    }

    let outcomes: Vec<_> = database_canonical
        .par_iter()
        .map_init(
            || (HashComputer::new(), vec![0_u8; 1024 * 1024]),
            |(computer, buffer), (db_path, entry)| {
                let outcome = if current_files.contains(db_path) {
                    // File exists, compute current hash using the mode specified in the database
                    let hash_result = std::fs::metadata(db_path)
                        .map_err(HashUtilityError::from)
                        .and_then(|metadata| {
                            computer.compute_hash_for_worker(
                                db_path,
                                &entry.algorithm,
                                entry.fast_mode,
                                metadata.len(),
                                buffer,
                            )
                        });

                    match hash_result {
                        Ok(result) => {
                            if result.hash == entry.hash {
                                Outcome::Match
                            } else {
                                Outcome::Mismatch(Mismatch {
                                    path: db_path.clone(),
                                    expected: entry.hash.clone(),
                                    actual: result.hash,
                                })
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to hash {}: {}", db_path.display(), e);
                            Outcome::Failed
                        }
                    }
                } else {
                    Outcome::Missing(db_path.clone())
                };
                pb.inc(1);
                outcome
            },
        )
        .collect();

    // Clear progress bar
    pb.finish_and_clear();

    // Find new files (in filesystem but not in database)
    let new_files: Vec<PathBuf> = current_files
        .iter()
        .filter(|path| !database_canonical.contains_key(*path))
        .cloned()
        .collect();

    let mut matches = 0;
    let mut mismatches = Vec::new();
    let mut missing_files = Vec::new();
    for outcome in outcomes {
        match outcome {
            Outcome::Match => matches += 1,
            Outcome::Mismatch(mismatch) => mismatches.push(mismatch),
            Outcome::Missing(path) => missing_files.push(path),
            Outcome::Failed => {}
        }
    }

    Ok(VerifyReport {
        matches,
        mismatches,
        missing_files,
        new_files,
    })
}

/// Optimized file collection using jwalk (same as scan)
pub(crate) fn collect_files_optimized(directory: &Path) -> Result<HashSet<PathBuf>, VerifyError> {
    use jwalk::WalkDir;

    let mut files = HashSet::new();
    let root = directory.canonicalize().map_err(|error| {
        HashUtilityError::from_io_error(error, "scanning directory", Some(directory.to_owned()))
    })?;

    // Use jwalk for fast parallel directory traversal (same configuration as scan)
    for entry_result in WalkDir::new(&root)
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

                files.insert(path);
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
    let canonical_base = base_directory
        .canonicalize()
        .unwrap_or_else(|_| base_directory.to_owned());

    for (path, entry) in database {
        // Use path_utils to resolve the path properly
        let absolute_path = path_utils::resolve_path(path, &canonical_base);
        let final_path = if path.is_absolute() {
            absolute_path.canonicalize().unwrap_or(absolute_path)
        } else {
            absolute_path
        };
        resolved.insert(final_path, entry.clone());
    }

    Ok(resolved)
}
