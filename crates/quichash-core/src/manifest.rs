//! Typed multi-algorithm manifests and deterministic folder digests.

use std::path::PathBuf;

use serde::Serialize;

use crate::error::HashUtilityError;
#[cfg(feature = "filesystem")]
use crate::hash::hash_file_mode;
use crate::hash::{Algorithm, DigestValue, HashMode, HasherSet};
#[cfg(feature = "filesystem")]
use crate::operation::{FailurePolicy, OperationObserver, ProgressEvent, ProgressPhase};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// One regular file and all of its recorded digests.
pub struct ManifestEntry {
    /// Path relative to the root represented by the manifest.
    pub relative_path: PathBuf,
    /// File length observed when the entry was created.
    pub size: u64,
    /// Whether the file was read completely or sampled.
    pub mode: HashMode,
    /// Validated digests recorded for the file.
    pub digests: Vec<DigestValue>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
/// A collection of typed file entries representing a directory tree.
pub struct Manifest {
    /// Files in the manifest.
    pub entries: Vec<ManifestEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// A deterministic digest derived from a canonical manifest.
pub struct FolderDigest {
    /// Algorithm used for the aggregate digest.
    pub algorithm: Algorithm,
    /// Aggregate digest value.
    pub digest: DigestValue,
}

#[cfg(feature = "filesystem")]
#[derive(Clone, Debug)]
/// Configuration for [`scan_folder`].
pub struct ScanOptions {
    /// Algorithms computed for every file and for the folder digest.
    pub algorithms: Vec<Algorithm>,
    /// Complete or sampled file hashing.
    pub mode: HashMode,
    /// Whether eligible file work may use Rayon.
    pub parallel: bool,
    /// Whether `.hashignore` rules should be applied.
    pub use_hashignore: bool,
    /// How item-level filesystem and hashing errors are handled.
    pub failure_policy: FailurePolicy,
    /// Optional file to omit, commonly a manifest written inside the root.
    pub exclude: Option<PathBuf>,
}

#[cfg(feature = "filesystem")]
impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            algorithms: vec![Algorithm::Blake3],
            mode: HashMode::Full,
            parallel: true,
            use_hashignore: true,
            failure_policy: FailurePolicy::FailFast,
            exclude: None,
        }
    }
}

#[cfg(feature = "filesystem")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Recoverable item-level problem retained under [`FailurePolicy::Continue`].
pub struct OperationIssue {
    /// Related path when the failing item is known.
    pub path: Option<PathBuf>,
    /// Human-readable error description.
    pub message: String,
}

#[cfg(feature = "filesystem")]
#[derive(Clone, Debug, Serialize)]
/// Successful folder scan output, including partial-operation issues.
pub struct ScanReport {
    /// Canonicalized per-file manifest.
    pub manifest: Manifest,
    /// One aggregate folder digest per requested algorithm.
    pub folder_digests: Vec<FolderDigest>,
    /// Number of regular files hashed successfully.
    pub files_processed: usize,
    /// Sum of the sizes of successfully hashed files.
    pub total_bytes: u64,
    /// Recoverable failures collected while continuing the operation.
    pub issues: Vec<OperationIssue>,
}

#[cfg(feature = "filesystem")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// One algorithm-specific difference between expected and actual file data.
pub struct DigestMismatch {
    /// Relative path of the changed file.
    pub path: PathBuf,
    /// Algorithm whose digest did not match.
    pub algorithm: Algorithm,
    /// Expected lowercase hexadecimal digest.
    pub expected: String,
    /// Actual lowercase hexadecimal digest.
    pub actual: String,
}

#[cfg(feature = "filesystem")]
#[derive(Clone, Debug, Default, Serialize)]
/// Result of comparing a typed manifest with a directory tree.
pub struct ManifestVerifyReport {
    /// Files for which every stored digest matched.
    pub matches: usize,
    /// Algorithm-specific digest differences.
    pub mismatches: Vec<DigestMismatch>,
    /// Expected relative paths that are absent or not regular files.
    pub missing_files: Vec<PathBuf>,
    /// Regular files found below the root but absent from the manifest.
    pub new_files: Vec<PathBuf>,
    /// Recoverable failures collected while continuing verification.
    pub issues: Vec<OperationIssue>,
}

impl Manifest {
    /// Sort entries and their digests into the canonical manifest order.
    pub fn canonicalize(&mut self) {
        self.entries.sort_by(|left, right| {
            canonical_path_bytes(&left.relative_path)
                .cmp(&canonical_path_bytes(&right.relative_path))
        });
        for entry in &mut self.entries {
            entry.digests.sort_by_key(|digest| digest.algorithm);
        }
    }

    /// Calculate one deterministic tree digest for each requested algorithm.
    ///
    /// The versioned encoding commits to canonical relative paths, sizes, hash
    /// modes, algorithm names, and all stored digest bytes. Input entry order
    /// and digest order do not change the result.
    pub fn folder_digests(
        &self,
        algorithms: &[Algorithm],
    ) -> Result<Vec<FolderDigest>, HashUtilityError> {
        let mut canonical = self.clone();
        canonical.canonicalize();
        let mut hashers = HasherSet::new(algorithms)?;
        hashers.update(b"quichash-folder-v1\0");
        for entry in &canonical.entries {
            let path = canonical_path_bytes(&entry.relative_path);
            hashers.update(&(path.len() as u64).to_le_bytes());
            hashers.update(&path);
            hashers.update(&entry.size.to_le_bytes());
            hashers.update(&[match entry.mode {
                HashMode::Full => 0,
                HashMode::Sampled => 1,
            }]);
            for digest in &entry.digests {
                let name = digest.algorithm.canonical_name().as_bytes();
                hashers.update(&(name.len() as u16).to_le_bytes());
                hashers.update(name);
                hashers.update(&(digest.bytes.len() as u16).to_le_bytes());
                hashers.update(&digest.bytes);
            }
        }
        Ok(hashers
            .finalize()
            .into_iter()
            .map(|digest| FolderDigest {
                algorithm: digest.algorithm,
                digest,
            })
            .collect())
    }
}

/// Recursively hash regular files and return a typed manifest.
///
/// Symbolic links are not followed. Hidden files are included unless ignored
/// by `.hashignore`. With [`FailurePolicy::FailFast`], the first operational
/// error is returned; with [`FailurePolicy::Continue`], item-level errors are
/// stored in [`ScanReport::issues`]. Cancellation always stops immediately.
#[cfg(feature = "filesystem")]
pub fn scan_folder(
    root: &std::path::Path,
    options: &ScanOptions,
    observer: &dyn OperationObserver,
) -> Result<ScanReport, HashUtilityError> {
    use jwalk::WalkDir;

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

/// Verify all stored digests against a local folder.
///
/// Every digest of each expected entry is recomputed using that entry's hash
/// mode. A file contributes to `matches` only if all digests match. The result
/// also identifies missing expected paths and new regular files.
#[cfg(feature = "filesystem")]
pub fn verify_folder(
    expected: &Manifest,
    root: &std::path::Path,
    failure_policy: FailurePolicy,
    observer: &dyn OperationObserver,
) -> Result<ManifestVerifyReport, HashUtilityError> {
    use jwalk::WalkDir;
    use std::collections::HashSet;

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
                })
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

fn canonical_path_bytes(path: &std::path::Path) -> Vec<u8> {
    let mut output = Vec::new();
    for (index, component) in path.components().enumerate() {
        if index > 0 {
            output.push(b'/');
        }
        let value = component.as_os_str();
        if let Some(text) = value.to_str() {
            output.extend_from_slice(text.as_bytes());
        } else {
            output.extend_from_slice(b"%native:");
            for byte in value.as_encoded_bytes() {
                use std::fmt::Write as _;
                let mut encoded = String::new();
                let _ = write!(encoded, "{byte:02x}");
                output.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_digest_is_independent_of_input_order() {
        let digest = |path: &str, value: u8| ManifestEntry {
            relative_path: path.into(),
            size: 1,
            mode: HashMode::Full,
            digests: vec![DigestValue {
                algorithm: Algorithm::Blake3,
                bytes: vec![value; 32],
            }],
        };
        let left = Manifest {
            entries: vec![digest("b", 2), digest("a", 1)],
        };
        let right = Manifest {
            entries: vec![digest("a", 1), digest("b", 2)],
        };
        assert_eq!(
            left.folder_digests(&[Algorithm::Blake3]).unwrap(),
            right.folder_digests(&[Algorithm::Blake3]).unwrap()
        );
    }

    #[test]
    fn rename_changes_folder_digest() {
        let entry = |path: &str| ManifestEntry {
            relative_path: path.into(),
            size: 3,
            mode: HashMode::Full,
            digests: vec![DigestValue {
                algorithm: Algorithm::Blake3,
                bytes: vec![7; 32],
            }],
        };
        let left = Manifest {
            entries: vec![entry("a")],
        };
        let right = Manifest {
            entries: vec![entry("b")],
        };
        assert_ne!(
            left.folder_digests(&[Algorithm::Blake3]).unwrap(),
            right.folder_digests(&[Algorithm::Blake3]).unwrap()
        );
    }

    #[test]
    fn sampled_and_full_folder_digests_are_distinct() {
        let entry = |mode| ManifestEntry {
            relative_path: "file".into(),
            size: 3,
            mode,
            digests: vec![DigestValue {
                algorithm: Algorithm::Blake3,
                bytes: vec![9; 32],
            }],
        };
        let full = Manifest {
            entries: vec![entry(HashMode::Full)],
        };
        let sampled = Manifest {
            entries: vec![entry(HashMode::Sampled)],
        };
        assert_ne!(
            full.folder_digests(&[Algorithm::Blake3]).unwrap(),
            sampled.folder_digests(&[Algorithm::Blake3]).unwrap(),
        );
    }

    #[cfg(all(feature = "filesystem", feature = "sha2", feature = "blake3"))]
    #[test]
    fn folder_scan_and_multi_digest_verification() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("nested")).unwrap();
        std::fs::write(temporary.path().join("a.txt"), b"alpha").unwrap();
        std::fs::write(temporary.path().join("nested/b.txt"), b"beta").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.txt", temporary.path().join("ignored-link")).unwrap();

        let options = ScanOptions {
            algorithms: vec![Algorithm::Blake3, Algorithm::Sha256],
            parallel: true,
            ..ScanOptions::default()
        };
        let scanned =
            scan_folder(temporary.path(), &options, &crate::operation::NoopObserver).unwrap();
        assert_eq!(scanned.manifest.entries.len(), 2);
        assert!(scanned
            .manifest
            .entries
            .iter()
            .all(|entry| entry.digests.len() == 2));
        assert_eq!(scanned.folder_digests.len(), 2);

        let verified = verify_folder(
            &scanned.manifest,
            temporary.path(),
            FailurePolicy::FailFast,
            &crate::operation::NoopObserver,
        )
        .unwrap();
        assert_eq!(verified.matches, 2);
        assert!(verified.mismatches.is_empty());

        std::fs::write(temporary.path().join("a.txt"), b"changed").unwrap();
        let verified = verify_folder(
            &scanned.manifest,
            temporary.path(),
            FailurePolicy::FailFast,
            &crate::operation::NoopObserver,
        )
        .unwrap();
        assert_eq!(verified.mismatches.len(), 2);
    }
}
