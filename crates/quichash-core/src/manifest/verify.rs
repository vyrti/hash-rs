use std::collections::HashSet;
use std::path::Path;

use jwalk::WalkDir;

use super::{DigestMismatch, Manifest, ManifestVerifyReport, OperationIssue};
use crate::error::HashUtilityError;
use crate::hash::hash_file_mode;
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
    for (index, entry) in expected.entries.iter().enumerate() {
        if observer.is_cancelled() {
            return Err(HashUtilityError::Cancelled);
        }
        expected_paths.insert(entry.relative_path.clone());
        let path = canonical_root.join(&entry.relative_path);
        if !path.is_file() {
            report.missing_files.push(entry.relative_path.clone());
            continue;
        }
        let algorithms: Vec<_> = entry
            .digests
            .iter()
            .map(|digest| digest.algorithm)
            .collect();
        let actual = match hash_file_mode(&path, &algorithms, entry.mode) {
            Ok(actual) => actual,
            Err(error) if failure_policy == FailurePolicy::Continue => {
                report.issues.push(OperationIssue {
                    path: Some(entry.relative_path.clone()),
                    message: error.to_string(),
                });
                continue;
            }
            Err(error) => return Err(error),
        };
        let mut matched = true;
        for (expected_digest, actual_digest) in entry.digests.iter().zip(actual) {
            if expected_digest.bytes != actual_digest.bytes {
                matched = false;
                report.mismatches.push(DigestMismatch {
                    path: entry.relative_path.clone(),
                    algorithm: expected_digest.algorithm,
                    expected: expected_digest.to_hex(),
                    actual: actual_digest.to_hex(),
                });
            }
        }
        if matched {
            report.matches += 1;
        }
        observer.on_progress(&ProgressEvent {
            phase: ProgressPhase::Verifying,
            completed: (index + 1) as u64,
            total: Some(expected.entries.len() as u64),
            bytes_processed: entry.size,
            path: Some(entry.relative_path.clone()),
        });
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
