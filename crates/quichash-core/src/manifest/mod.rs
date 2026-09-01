//! Typed multi-algorithm manifests and deterministic folder digests.

use std::path::PathBuf;

use serde::Serialize;

use crate::error::HashUtilityError;
use crate::hash::{Algorithm, DigestValue, HashMode, HasherSet};
#[cfg(feature = "filesystem")]
use crate::operation::FailurePolicy;

#[cfg(feature = "filesystem")]
mod scan;
#[cfg(feature = "filesystem")]
mod verify;

#[cfg(feature = "filesystem")]
pub use scan::scan_folder;
#[cfg(feature = "filesystem")]
pub use verify::verify_folder;

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
#[non_exhaustive]
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
impl ScanOptions {
    /// Create new default [`ScanOptions`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the algorithms to compute.
    pub fn with_algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Set the hashing mode (Full or Sampled).
    pub fn with_mode(mut self, mode: HashMode) -> Self {
        self.mode = mode;
        self
    }

    /// Enable or disable parallel processing.
    pub fn with_parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }

    /// Enable or disable `.hashignore` parsing.
    pub fn with_hashignore(mut self, use_hashignore: bool) -> Self {
        self.use_hashignore = use_hashignore;
        self
    }

    /// Set the failure policy.
    pub fn with_failure_policy(mut self, failure_policy: FailurePolicy) -> Self {
        self.failure_policy = failure_policy;
        self
    }

    /// Exclude a specific path (e.g. output database).
    pub fn with_exclude(mut self, exclude: Option<PathBuf>) -> Self {
        self.exclude = exclude;
        self
    }
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
#[non_exhaustive]
/// Recoverable item-level problem retained under [`FailurePolicy::Continue`].
pub struct OperationIssue {
    /// Related path when the failing item is known.
    pub path: Option<PathBuf>,
    /// Human-readable error description.
    pub message: String,
}

#[cfg(feature = "filesystem")]
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
        self.entries
            .sort_by_cached_key(|entry| canonical_path_bytes(&entry.relative_path));
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
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by_cached_key(|entry| canonical_path_bytes(&entry.relative_path));
        let mut hashers = HasherSet::new(algorithms)?;
        hashers.update(b"quichash-folder-v1\0");
        for entry in entries {
            let path = canonical_path_bytes(&entry.relative_path);
            hashers.update(&(path.len() as u64).to_le_bytes());
            hashers.update(&path);
            hashers.update(&entry.size.to_le_bytes());
            hashers.update(&[match entry.mode {
                HashMode::Full => 0,
                HashMode::Sampled => 1,
            }]);
            let mut digests: Vec<_> = entry.digests.iter().collect();
            digests.sort_by_key(|digest| digest.algorithm);
            for digest in digests {
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

pub(crate) fn canonical_path_bytes(path: &std::path::Path) -> Vec<u8> {
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
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for byte in value.as_encoded_bytes() {
                output.push(HEX[(byte >> 4) as usize]);
                output.push(HEX[(byte & 0x0f) as usize]);
            }
        }
    }
    output
}
