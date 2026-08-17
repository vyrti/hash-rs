//! Manifest verification.
// Compares current hashes against stored database

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::database::{DatabaseEntry, DatabaseHandler};
use crate::error::HashUtilityError;
use crate::hash::HashComputer;

mod engine;
mod report;
#[cfg(test)]
mod tests;

pub use engine::VerifyError;
pub use report::{Mismatch, VerifyReport};

/// Engine for verifying file integrity against a hash database
pub struct VerifyEngine {
    computer: HashComputer,
    parallel: bool,
}

impl VerifyEngine {
    /// Create a new VerifyEngine with parallel processing (default)
    pub fn new() -> Self {
        Self {
            computer: HashComputer::new(),
            parallel: true,
        }
    }

    /// Create a new VerifyEngine with parallel processing control
    pub fn with_parallel(parallel: bool) -> Self {
        Self {
            computer: HashComputer::new(),
            parallel,
        }
    }

    /// Verify directory contents against a hash database
    ///
    /// This function:
    /// 1. Loads the hash database from the specified file
    /// 2. Recursively scans the directory to find all files
    /// 3. Computes current hashes for files in the database
    /// 4. Classifies files as: matches, mismatches, missing, or new
    /// 5. Returns a detailed report
    pub fn verify(
        &self,
        database_path: &Path,
        directory: &Path,
    ) -> Result<VerifyReport, VerifyError> {
        // Verify database file exists
        if !database_path.exists() {
            return Err(HashUtilityError::DatabaseNotFound {
                path: database_path.to_path_buf(),
            });
        }

        // Verify directory exists
        if !directory.exists() || !directory.is_dir() {
            return Err(HashUtilityError::DirectoryNotFound {
                path: directory.to_path_buf(),
            });
        }

        if let Some(algorithm) = DatabaseHandler::verification_checksum_algorithm(database_path)? {
            if !algorithm.is_available() {
                return Err(HashUtilityError::AlgorithmUnavailable {
                    algorithm: algorithm.canonical_name().to_owned(),
                    feature: algorithm.required_feature(),
                });
            }
            let manifest = DatabaseHandler::read_checksum_manifest(database_path)?;
            let database = manifest
                .entries
                .into_iter()
                .filter_map(|entry| {
                    entry.digests.into_iter().next().map(|digest| {
                        (
                            entry.relative_path,
                            DatabaseEntry {
                                hash: digest.to_hex(),
                                algorithm: digest.algorithm.canonical_name().to_owned(),
                                fast_mode: entry.mode == crate::hash::HashMode::Sampled,
                            },
                        )
                    })
                })
                .collect();
            return self.verify_database_entries(database, database_path, directory);
        }

        let manifest = DatabaseHandler::read_manifest_with_policy(
            database_path,
            crate::operation::FailurePolicy::Continue,
        )?
        .manifest;
        if manifest
            .entries
            .iter()
            .all(|entry| entry.digests.len() == 1)
        {
            let database = DatabaseHandler::read_database(database_path)?;
            let database_canonical_path = database_path.canonicalize().ok();
            let mut current_files = engine::collect_files_optimized(directory)?;
            if let Some(path) = &database_canonical_path {
                current_files.remove(path);
            }
            let database = engine::resolve_database_paths_optimized(&database, directory)?;
            return if self.parallel {
                engine::verify_parallel(database, current_files)
            } else {
                engine::verify_sequential(&self.computer, database, current_files)
            };
        }
        let typed = crate::manifest::verify_folder(
            &manifest,
            directory,
            crate::operation::FailurePolicy::Continue,
            &crate::operation::NoopObserver,
        )?;
        let root = directory
            .canonicalize()
            .unwrap_or_else(|_| directory.to_owned());
        let database_canonical = database_path.canonicalize().ok();
        let absolute = |path: PathBuf| {
            let joined = root.join(path);
            joined.canonicalize().unwrap_or(joined)
        };
        let mut new_files: Vec<_> = typed.new_files.into_iter().map(absolute).collect();
        if let Some(database) = database_canonical {
            new_files.retain(|path| path != &database);
        }
        Ok(VerifyReport {
            matches: typed.matches,
            mismatches: typed
                .mismatches
                .into_iter()
                .map(|mismatch| Mismatch {
                    path: absolute(mismatch.path),
                    expected: mismatch.expected,
                    actual: mismatch.actual,
                })
                .collect(),
            missing_files: typed.missing_files.into_iter().map(absolute).collect(),
            new_files,
        })
    }

    fn verify_database_entries(
        &self,
        database: HashMap<PathBuf, DatabaseEntry>,
        database_path: &Path,
        directory: &Path,
    ) -> Result<VerifyReport, VerifyError> {
        let database_canonical_path = database_path.canonicalize().ok();
        let mut current_files = engine::collect_files_optimized(directory)?;
        if let Some(path) = &database_canonical_path {
            current_files.remove(path);
        }
        let database = engine::resolve_database_paths_optimized(&database, directory)?;
        if self.parallel {
            engine::verify_parallel(database, current_files)
        } else {
            engine::verify_sequential(&self.computer, database, current_files)
        }
    }

    /// Legacy method for backward compatibility
    #[allow(dead_code)]
    fn collect_files(&self, directory: &Path) -> Result<HashSet<PathBuf>, VerifyError> {
        engine::collect_files_optimized(directory)
    }

    /// Legacy method for backward compatibility
    #[allow(dead_code)]
    fn resolve_database_paths(
        &self,
        database: &HashMap<PathBuf, DatabaseEntry>,
        base_directory: &Path,
    ) -> Result<HashMap<PathBuf, DatabaseEntry>, VerifyError> {
        engine::resolve_database_paths_optimized(database, base_directory)
    }
}

impl Default for VerifyEngine {
    fn default() -> Self {
        Self::new()
    }
}
