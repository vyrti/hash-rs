use std::collections::HashSet;
use std::path::Path;

use jwalk::WalkDir;

use super::{DigestMismatch, Manifest, ManifestVerifyReport, OperationIssue};
use crate::error::HashUtilityError;
use crate::hash::file::hash_file_mode_worker;
use crate::operation::{FailurePolicy, OperationObserver, ProgressEvent, ProgressPhase};

/// Verify all stored digests against a local folder.
///
/// Every digest of each expected entry is recomputed using that entry's hash
/// mode. A file contributes to `matches` only if all digests match. The result
/// also identifies missing expected paths and new regular files.
pub fn verify_folder(
    expected: &Manifest,
    root: &Path,
    failure_policy: FailurePolicy,
    observer: &dyn OperationObserver,
) -> Result<ManifestVerifyReport, HashUtilityError> {
    let canonical_root = root.canonicalize().map_err(|error| {
        HashUtilityError::from_io_error(error, "verifying directory", Some(root.to_owned()))
    })?;
    let mut report = ManifestVerifyReport::default();
    let mut expected_paths = HashSet::new();
    for entry in &expected.entries {
        expected_paths.insert(entry.relative_path.clone());
    }

    struct Verified {
        matched: bool,
        missing: bool,
        mismatches: Vec<DigestMismatch>,
    }
    let completed = std::sync::atomic::AtomicU64::new(0);
    let processed_bytes = std::sync::atomic::AtomicU64::new(0);
    let verify = |entry: &super::ManifestEntry,
                  buffer: &mut Vec<u8>|
     -> Result<Verified, HashUtilityError> {
        if observer.is_cancelled() {
            return Err(HashUtilityError::Cancelled);
        }
        let path = canonical_root.join(&entry.relative_path);
        if !path.is_file() {
            return Ok(Verified {
                matched: false,
                missing: true,
                mismatches: Vec::new(),
            });
        }
        let algorithms: Vec<_> = entry
            .digests
            .iter()
            .map(|digest| digest.algorithm)
            .collect();
        let size = path
            .metadata()
            .map_err(|error| {
                HashUtilityError::from_io_error(error, "reading metadata", Some(path.clone()))
            })?
            .len();
        let actual = hash_file_mode_worker(&path, &algorithms, entry.mode, size, buffer)?;
        let mut matched = true;
        let mut mismatches = Vec::new();
        for (expected_digest, actual_digest) in entry.digests.iter().zip(actual) {
            if expected_digest.bytes != actual_digest.bytes {
                matched = false;
                mismatches.push(DigestMismatch {
                    path: entry.relative_path.clone(),
                    algorithm: expected_digest.algorithm,
                    expected: expected_digest.to_hex(),
                    actual: actual_digest.to_hex(),
                });
            }
        }
        let completed = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let bytes_processed =
            processed_bytes.fetch_add(size, std::sync::atomic::Ordering::Relaxed) + size;
        observer.on_progress(&ProgressEvent {
            phase: ProgressPhase::Verifying,
            completed,
            total: Some(expected.entries.len() as u64),
            bytes_processed,
            path: Some(entry.relative_path.clone()),
        });
        Ok(Verified {
            matched,
            missing: false,
            mismatches,
        })
    };

    #[cfg(feature = "parallel")]
    let results: Vec<_> = {
        use rayon::prelude::*;
        expected
            .entries
            .par_iter()
            .map_init(
                || vec![0_u8; 1024 * 1024],
                |buffer, entry| verify(entry, buffer),
            )
            .collect()
    };
    #[cfg(not(feature = "parallel"))]
    let results: Vec<_> = {
        let mut buffer = vec![0_u8; 1024 * 1024];
        expected
            .entries
            .iter()
            .map(|entry| verify(entry, &mut buffer))
            .collect()
    };

    for (entry, result) in expected.entries.iter().zip(results) {
        match result {
            Ok(verified) => {
                if verified.missing {
                    report.missing_files.push(entry.relative_path.clone());
                } else if verified.matched {
                    report.matches += 1;
                }
                report.mismatches.extend(verified.mismatches);
            }
            Err(HashUtilityError::Cancelled) => return Err(HashUtilityError::Cancelled),
            Err(error) if failure_policy == FailurePolicy::Continue => {
                report.issues.push(OperationIssue {
                    path: Some(entry.relative_path.clone()),
                    message: error.to_string(),
                });
            }
            Err(error) => return Err(error),
        }
    }
    for result in WalkDir::new(&canonical_root)
        .parallelism(if cfg!(feature = "parallel") {
            jwalk::Parallelism::RayonNewPool(0)
        } else {
            jwalk::Parallelism::Serial
        })
        .skip_hidden(false)
        .follow_links(false)
    {
        let item = match result {
            Ok(item) => item,
            Err(error) if failure_policy == FailurePolicy::Continue => {
                report.issues.push(OperationIssue {
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
        if item.file_type().is_file() {
            let path = item.path();
            let relative = path
                .strip_prefix(&canonical_root)
                .unwrap_or(&path)
                .to_owned();
            if !expected_paths.contains(&relative) {
                report.new_files.push(relative);
            }
        }
    }
    report.missing_files.sort();
    report.new_files.sort();
    Ok(report)
}
