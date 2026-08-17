//! Hash computation primitives and optimized file helpers.
// Provides hash algorithm registry and computation logic

use std::path::PathBuf;

use crate::error::HashUtilityError;

pub(crate) mod algorithm;
pub(crate) mod computer;
pub(crate) mod file;
pub(crate) mod hasher;
pub(crate) mod registry;
#[cfg(test)]
mod tests;

pub use algorithm::{Algorithm, AlgorithmInfo, DigestValue, HashMode};
pub use computer::HashComputer;
pub use file::{hash_bytes, hash_file, hash_file_mode, hash_reader, hash_reader_observed};
#[cfg(feature = "blake3")]
pub use hasher::Blake3Wrapper;
#[cfg(feature = "md5")]
pub use hasher::Md5Wrapper;
#[cfg(feature = "sha1")]
pub use hasher::Sha1Wrapper;
#[cfg(feature = "blake2")]
pub use hasher::{Blake2b512Wrapper, Blake2s256Wrapper};
pub use hasher::{Hasher, HasherSet};
#[cfg(feature = "sha2")]
pub use hasher::{Sha224Wrapper, Sha256Wrapper, Sha384Wrapper, Sha512Wrapper};
#[cfg(feature = "sha3")]
pub use hasher::{Sha3_224Wrapper, Sha3_256Wrapper, Sha3_384Wrapper, Sha3_512Wrapper};
#[cfg(feature = "xxhash")]
pub use hasher::{Xxh128Wrapper, Xxh3Wrapper};
pub use registry::HashRegistry;

// Re-export HashUtilityError as HashError for backward compatibility
/// Backward-compatible name for [`HashUtilityError`].
pub type HashError = HashUtilityError;

/// Result of a hash computation
#[derive(Debug, Clone, serde::Serialize)]
pub struct HashResult {
    /// Algorithm name supplied to the compatibility API.
    pub algorithm: String,
    /// Lowercase hexadecimal digest.
    pub hash: String, // hex-encoded
    /// Source path, or a synthetic marker such as `<text>` or `<stdin>`.
    pub file_path: PathBuf,
}
