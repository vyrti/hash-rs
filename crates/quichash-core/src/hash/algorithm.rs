use std::fmt;
use std::str::FromStr;

use super::hasher::{Hasher, bytes_to_hex};
use super::registry::HashRegistry;
use crate::error::HashUtilityError;

/// Stable identifier for every algorithm understood by QuicHash.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Algorithm {
    /// MD5 with a 128-bit output.
    Md5,
    /// SHA-1 with a 160-bit output.
    Sha1,
    /// SHA-224 from the SHA-2 family.
    Sha224,
    /// SHA-256 from the SHA-2 family.
    Sha256,
    /// SHA-384 from the SHA-2 family.
    Sha384,
    /// SHA-512 from the SHA-2 family.
    Sha512,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// BLAKE2b with a 512-bit output.
    Blake2b512,
    /// BLAKE2s with a 256-bit output.
    Blake2s256,
    /// BLAKE3 with its standard 256-bit output.
    Blake3,
    /// XXH3 with a 64-bit output.
    Xxh3,
    /// XXH3 with a 128-bit output.
    Xxh128,
}

impl Algorithm {
    /// Every algorithm identifier understood by this version of the crate.
    ///
    /// The array includes algorithms that may have been disabled through Cargo
    /// features. Use [`Algorithm::is_available`] to filter it.
    pub const ALL: [Self; 15] = [
        Self::Md5,
        Self::Sha1,
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
        Self::Blake2b512,
        Self::Blake2s256,
        Self::Blake3,
        Self::Xxh3,
        Self::Xxh128,
    ];

    /// Return the stable lowercase name used in manifests and string parsing.
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha3_224 => "sha3-224",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
            Self::Blake2b512 => "blake2b-512",
            Self::Blake2s256 => "blake2s-256",
            Self::Blake3 => "blake3",
            Self::Xxh3 => "xxh3",
            Self::Xxh128 => "xxh128",
        }
    }

    /// Return a human-readable algorithm name.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha3_224 => "SHA3-224",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
            Self::Blake2b512 => "BLAKE2b-512",
            Self::Blake2s256 => "BLAKE2s-256",
            Self::Blake3 => "BLAKE3",
            Self::Xxh3 => "XXH3",
            Self::Xxh128 => "XXH128",
        }
    }

    /// Return the digest size in bytes.
    pub const fn output_size(self) -> usize {
        match self {
            Self::Md5 | Self::Xxh128 => 16,
            Self::Sha1 => 20,
            Self::Sha224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha3_256 | Self::Blake2s256 | Self::Blake3 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 | Self::Blake2b512 => 64,
            Self::Xxh3 => 8,
        }
    }

    /// Return the Cargo feature that provides this implementation.
    pub const fn required_feature(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha224 | Self::Sha256 | Self::Sha384 | Self::Sha512 => "sha2",
            Self::Sha3_224 | Self::Sha3_256 | Self::Sha3_384 | Self::Sha3_512 => "sha3",
            Self::Blake2b512 | Self::Blake2s256 => "blake2",
            Self::Blake3 => "blake3",
            Self::Xxh3 | Self::Xxh128 => "xxhash",
        }
    }

    /// Return whether this algorithm was compiled into the current build.
    pub const fn is_available(self) -> bool {
        match self {
            Self::Md5 => cfg!(feature = "md5"),
            Self::Sha1 => cfg!(feature = "sha1"),
            Self::Sha224 | Self::Sha256 | Self::Sha384 | Self::Sha512 => cfg!(feature = "sha2"),
            Self::Sha3_224 | Self::Sha3_256 | Self::Sha3_384 | Self::Sha3_512 => {
                cfg!(feature = "sha3")
            }
            Self::Blake2b512 | Self::Blake2s256 => cfg!(feature = "blake2"),
            Self::Blake3 => cfg!(feature = "blake3"),
            Self::Xxh3 | Self::Xxh128 => cfg!(feature = "xxhash"),
        }
    }

    /// Construct a fresh streaming hasher for this algorithm.
    ///
    /// Returns [`HashUtilityError::AlgorithmUnavailable`] when the corresponding
    /// Cargo feature is disabled.
    pub fn hasher(self) -> Result<Box<dyn Hasher>, HashUtilityError> {
        HashRegistry::get_hasher(self.canonical_name())
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.canonical_name())
    }
}

impl FromStr for Algorithm {
    type Err = HashUtilityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "md5" => Ok(Self::Md5),
            "sha1" | "sha-1" => Ok(Self::Sha1),
            "sha224" | "sha-224" => Ok(Self::Sha224),
            "sha256" | "sha-256" => Ok(Self::Sha256),
            "sha384" | "sha-384" => Ok(Self::Sha384),
            "sha512" | "sha-512" => Ok(Self::Sha512),
            "sha3-224" => Ok(Self::Sha3_224),
            "sha3-256" => Ok(Self::Sha3_256),
            "sha3-384" => Ok(Self::Sha3_384),
            "sha3-512" => Ok(Self::Sha3_512),
            "blake2b" | "blake2b-512" => Ok(Self::Blake2b512),
            "blake2s" | "blake2s-256" => Ok(Self::Blake2s256),
            "blake3" => Ok(Self::Blake3),
            "xxh3" => Ok(Self::Xxh3),
            "xxh128" => Ok(Self::Xxh128),
            _ => Err(HashUtilityError::UnsupportedAlgorithm {
                algorithm: value.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
/// Selects complete or sampled file hashing.
pub enum HashMode {
    /// Hash the complete contents of the file.
    #[default]
    Full,
    /// Hash three fixed-size samples of a large file for quick identification.
    Sampled,
}

/// A validated binary digest coupled to its algorithm.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DigestValue {
    /// Algorithm that produced the digest.
    pub algorithm: Algorithm,
    pub(crate) bytes: Vec<u8>,
}

impl DigestValue {
    /// Validate raw digest bytes and associate them with `algorithm`.
    ///
    /// The byte length must equal [`Algorithm::output_size`].
    pub fn from_bytes(algorithm: Algorithm, bytes: Vec<u8>) -> Result<Self, HashUtilityError> {
        if bytes.len() != algorithm.output_size() {
            return Err(HashUtilityError::InvalidDigest {
                algorithm: algorithm.to_string(),
                reason: format!(
                    "expected {} bytes, found {}",
                    algorithm.output_size(),
                    bytes.len()
                ),
            });
        }
        Ok(Self { algorithm, bytes })
    }

    /// Decode and validate a hexadecimal digest for `algorithm`.
    pub fn from_hex(algorithm: Algorithm, value: &str) -> Result<Self, HashUtilityError> {
        if value.len() != algorithm.output_size() * 2 {
            return Err(HashUtilityError::InvalidDigest {
                algorithm: algorithm.to_string(),
                reason: format!(
                    "expected {} hexadecimal characters, found {}",
                    algorithm.output_size() * 2,
                    value.len()
                ),
            });
        }
        let bytes = value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("hexadecimal text is ASCII");
                u8::from_str_radix(text, 16).map_err(|_| HashUtilityError::InvalidDigest {
                    algorithm: algorithm.to_string(),
                    reason: "digest contains a non-hexadecimal character".to_owned(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { algorithm, bytes })
    }

    /// Encode the digest as lowercase hexadecimal text.
    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.bytes)
    }

    /// Borrow the validated binary digest.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Information about a hash algorithm
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct AlgorithmInfo {
    /// Human-readable algorithm name.
    pub name: String,
    /// Digest size in bits.
    pub output_bits: usize,
    /// Whether the registry classifies the algorithm as post-quantum resistant.
    pub post_quantum: bool,
    /// Whether the algorithm is intended to provide cryptographic hashing.
    pub cryptographic: bool,
}
