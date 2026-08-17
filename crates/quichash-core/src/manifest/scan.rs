use std::path::{Path, PathBuf};

use jwalk::WalkDir;

use super::{Manifest, ManifestEntry, OperationIssue, ScanOptions, ScanReport};
use crate::error::HashUtilityError;
use crate::hash::hash_file_mode;
use crate::operation::{FailurePolicy, OperationObserver, ProgressEvent, ProgressPhase};

/// Recursively hash regular files and return a typed manifest.
///
/// Symbolic links are not followed. Hidden files are included unless ignored
/// by `.hashignore`. With [`FailurePolicy::FailFast`], the first operational
/// error is returned; with [`FailurePolicy::Continue`], item-level errors are
/// stored in [`ScanReport::issues`]. Cancellation always stops immediately.
pub fn scan_folder(
    root: &Path,
    options: &ScanOptions,
    observer: &dyn OperationObserver,
) -> Result<ScanReport, HashUtilityError> {
    if options.algorithms.is_empty() {
        return Err(HashUtilityError::InvalidArguments {
            message: "at least one hash algorithm is required".to_owned(),
        });
    }
    for algorithm in &options.algorithms {
        if !algorithm.is_available() {
            return Err(HashUtilityError::AlgorithmUnavailable {
                algorithm: algorithm.to_string(),
                feature: algorithm.required_feature(),
            });
        }
    }
    let canonical_root = root.canonicalize().map_err(|error| {
        HashUtilityError::from_io_error(error, "scanning directory", Some(root.to_owned()))
    })?;
    if !canonical_root.is_dir() {
        return Err(HashUtilityError::DirectoryNotFound {
            path: root.to_owned(),
        });
    }
    let exclude = options
        .exclude
        .as_ref()
        .and_then(|path| path.canonicalize().ok());
    let mut issues = Vec::new();
    let ignore = if options.use_hashignore {
        match crate::ignore_handler::IgnoreHandler::new(&canonical_root) {
            Ok(value) => Some(value),
            Err(error) if options.failure_policy == FailurePolicy::Continue => {
                issues.push(OperationIssue {
                    path: Some(canonical_root.clone()),
                    message: error.to_string(),
                });
                None
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let mut paths = Vec::new();
    let parallelism = if options.parallel && cfg!(feature = "parallel") {
        jwalk::Parallelism::RayonNewPool(0)
    } else {
        jwalk::Parallelism::Serial
    };
    for result in WalkDir::new(&canonical_root)
        .parallelism(parallelism)
        .skip_hidden(false)
        .follow_links(false)
    {
        if observer.is_cancelled() {
            return Err(HashUtilityError::Cancelled);
        }
        let entry = match result {
            Ok(entry) => entry,
            Err(error) if options.failure_policy == FailurePolicy::Continue => {
                issues.push(OperationIssue {
                    path: None,
                    message: error.to_string(),
                });
                continue;
            }
            Err(error) => {
                return Err(HashUtilityError::VerificationFailed {
                    reason: error.to_string(),
                });
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if exclude.as_ref().is_some_and(|excluded| path == *excluded) {
            continue;
        }
        let relative = path.strip_prefix(&canonical_root).unwrap_or(&path);
        if ignore
            .as_ref()
            .is_some_and(|handler| handler.should_ignore(relative, false))
        {
            continue;
        }
        paths.push(path);
        observer.on_progress(&ProgressEvent {
            phase: ProgressPhase::Discovering,
            completed: paths.len() as u64,
            total: None,
            bytes_processed: 0,
            path: None,
        });
    }

    let completed = std::sync::atomic::AtomicU64::new(0);
    let processed_bytes = std::sync::atomic::AtomicU64::new(0);
    let process = |path: &PathBuf| -> Result<ManifestEntry, HashUtilityError> {
        if observer.is_cancelled() {
            return Err(HashUtilityError::Cancelled);
        }
        let size = path
            .metadata()
            .map_err(|error| {
                HashUtilityError::from_io_error(error, "reading metadata", Some(path.clone()))
            })?
            .len();
        let digests = hash_file_mode(path, &options.algorithms, options.mode)?;
        let completed = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let bytes_processed =
            processed_bytes.fetch_add(size, std::sync::atomic::Ordering::Relaxed) + size;
        observer.on_progress(&ProgressEvent {
            phase: ProgressPhase::Hashing,
            completed,
            total: Some(paths.len() as u64),
            bytes_processed,
            path: Some(path.clone()),
        });
        Ok(ManifestEntry {
            relative_path: path
                .strip_prefix(&canonical_root)
                .unwrap_or(path)
                .to_owned(),
            size,
            mode: options.mode,
            digests,
        })
    };

    #[cfg(feature = "parallel")]
    let results: Vec<_> = if options.parallel {
        use rayon::prelude::*;
        paths.par_iter().map(process).collect()
    } else {
        paths.iter().map(process).collect()
    };
    #[cfg(not(feature = "parallel"))]
    let results: Vec<_> = paths.iter().map(process).collect();

    let mut entries = Vec::new();
    for (path, result) in paths.iter().zip(results) {
        match result {
            Ok(entry) => entries.push(entry),
            Err(HashUtilityError::Cancelled) => return Err(HashUtilityError::Cancelled),
            Err(error) if options.failure_policy == FailurePolicy::Continue => {
                issues.push(OperationIssue {
                    path: Some(path.clone()),
                    message: error.to_string(),
                });
            }
            Err(error) => return Err(error),
        }
    }
    let total_bytes = entries.iter().map(|entry| entry.size).sum();
    let mut manifest = Manifest { entries };
    manifest.canonicalize();
    let folder_digests = manifest.folder_digests(&options.algorithms)?;
    Ok(ScanReport {
        files_processed: manifest.entries.len(),
        manifest,
        folder_digests,
        total_bytes,
        issues,
    })
}
