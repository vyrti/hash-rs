use super::algorithm::{Algorithm, DigestValue};
use crate::error::HashUtilityError;

// Wrapper types for hash algorithms
#[cfg(feature = "blake2")]
use blake2::{Blake2b512, Blake2s256, Digest as Blake2Digest};
#[cfg(feature = "blake3")]
pub(crate) use blake3::Hasher as Blake3Hasher;
#[cfg(feature = "md5")]
use md5::{Digest as Md5Digest, Md5};
#[cfg(feature = "sha1")]
use sha1::{Digest as Sha1Digest, Sha1};
#[cfg(feature = "sha2")]
use sha2::{Digest as Sha2Digest, Sha224, Sha256, Sha384, Sha512};
#[cfg(feature = "sha3")]
use sha3::{Digest as Sha3Digest, Sha3_224, Sha3_256, Sha3_384, Sha3_512};
#[cfg(feature = "xxhash")]
use xxhash_rust::xxh3::Xxh3 as Xxh3Hasher;
#[cfg(feature = "xxhash")]
use xxhash_rust::xxh3::Xxh3 as Xxh3HasherBase;

/// Trait for hash algorithm implementations
pub trait Hasher: Send {
    /// Update the hasher with new data
    fn update(&mut self, data: &[u8]);

    /// Finalize the hash and return the result
    fn finalize(self: Box<Self>) -> Vec<u8>;

    /// Get the output size in bytes
    fn output_size(&self) -> usize;
}

/// Streaming MD5 implementation used by the compatibility registry.
#[cfg(feature = "md5")]
pub struct Md5Wrapper(pub(crate) Md5);

#[cfg(feature = "md5")]
impl Hasher for Md5Wrapper {
    fn update(&mut self, data: &[u8]) {
        Md5Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Md5Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        16 // 128 bits
    }
}

// SHA1 wrapper
/// Streaming SHA-1 implementation used by the compatibility registry.
#[cfg(feature = "sha1")]
pub struct Sha1Wrapper(pub(crate) Sha1);

#[cfg(feature = "sha1")]
impl Hasher for Sha1Wrapper {
    fn update(&mut self, data: &[u8]) {
        Sha1Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Sha1Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        20 // 160 bits
    }
}

// SHA-224 wrapper
/// Streaming SHA-224 implementation used by the compatibility registry.
#[cfg(feature = "sha2")]
pub struct Sha224Wrapper(pub(crate) Sha224);

#[cfg(feature = "sha2")]
impl Hasher for Sha224Wrapper {
    fn update(&mut self, data: &[u8]) {
        Sha2Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Sha2Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        28 // 224 bits
    }
}

// SHA-256 wrapper
/// Streaming SHA-256 implementation used by the compatibility registry.
#[cfg(feature = "sha2")]
pub struct Sha256Wrapper(pub(crate) Sha256);

#[cfg(feature = "sha2")]
impl Hasher for Sha256Wrapper {
    fn update(&mut self, data: &[u8]) {
        Sha2Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Sha2Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        32 // 256 bits
    }
}

// SHA-384 wrapper
/// Streaming SHA-384 implementation used by the compatibility registry.
#[cfg(feature = "sha2")]
pub struct Sha384Wrapper(pub(crate) Sha384);

#[cfg(feature = "sha2")]
impl Hasher for Sha384Wrapper {
    fn update(&mut self, data: &[u8]) {
        Sha2Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Sha2Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        48 // 384 bits
    }
}

// SHA-512 wrapper
/// Streaming SHA-512 implementation used by the compatibility registry.
#[cfg(feature = "sha2")]
pub struct Sha512Wrapper(pub(crate) Sha512);

#[cfg(feature = "sha2")]
impl Hasher for Sha512Wrapper {
    fn update(&mut self, data: &[u8]) {
        Sha2Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Sha2Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        64 // 512 bits
    }
}

// SHA3-224 wrapper
/// Streaming SHA3-224 implementation used by the compatibility registry.
#[cfg(feature = "sha3")]
pub struct Sha3_224Wrapper(pub(crate) Sha3_224);

#[cfg(feature = "sha3")]
impl Hasher for Sha3_224Wrapper {
    fn update(&mut self, data: &[u8]) {
        Sha3Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Sha3Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        28 // 224 bits
    }
}

// SHA3-256 wrapper
/// Streaming SHA3-256 implementation used by the compatibility registry.
#[cfg(feature = "sha3")]
pub struct Sha3_256Wrapper(pub(crate) Sha3_256);

#[cfg(feature = "sha3")]
impl Hasher for Sha3_256Wrapper {
    fn update(&mut self, data: &[u8]) {
        Sha3Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Sha3Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        32 // 256 bits
    }
}

// SHA3-384 wrapper
/// Streaming SHA3-384 implementation used by the compatibility registry.
#[cfg(feature = "sha3")]
pub struct Sha3_384Wrapper(pub(crate) Sha3_384);

#[cfg(feature = "sha3")]
impl Hasher for Sha3_384Wrapper {
    fn update(&mut self, data: &[u8]) {
        Sha3Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Sha3Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        48 // 384 bits
    }
}

// SHA3-512 wrapper
/// Streaming SHA3-512 implementation used by the compatibility registry.
#[cfg(feature = "sha3")]
pub struct Sha3_512Wrapper(pub(crate) Sha3_512);

#[cfg(feature = "sha3")]
impl Hasher for Sha3_512Wrapper {
    fn update(&mut self, data: &[u8]) {
        Sha3Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Sha3Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        64 // 512 bits
    }
}

// BLAKE2b wrapper
/// Streaming BLAKE2b-512 implementation used by the compatibility registry.
#[cfg(feature = "blake2")]
pub struct Blake2b512Wrapper(pub(crate) Blake2b512);

#[cfg(feature = "blake2")]
impl Hasher for Blake2b512Wrapper {
    fn update(&mut self, data: &[u8]) {
        Blake2Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Blake2Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        64 // 512 bits
    }
}

// BLAKE2s wrapper
/// Streaming BLAKE2s-256 implementation used by the compatibility registry.
#[cfg(feature = "blake2")]
pub struct Blake2s256Wrapper(pub(crate) Blake2s256);

#[cfg(feature = "blake2")]
impl Hasher for Blake2s256Wrapper {
    fn update(&mut self, data: &[u8]) {
        Blake2Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        Blake2Digest::finalize(self.0).to_vec()
    }

    fn output_size(&self) -> usize {
        32 // 256 bits
    }
}

// BLAKE3 wrapper
/// Streaming BLAKE3 implementation used by the compatibility registry.
#[cfg(feature = "blake3")]
pub struct Blake3Wrapper(pub(crate) Blake3Hasher);

#[cfg(feature = "blake3")]
impl Hasher for Blake3Wrapper {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.finalize().as_bytes().to_vec()
    }

    fn output_size(&self) -> usize {
        32 // 256 bits
    }
}

/// Streaming XXH3-64 implementation used by the compatibility registry.
#[cfg(feature = "xxhash")]
pub struct Xxh3Wrapper(pub(crate) Xxh3Hasher);

#[cfg(feature = "xxhash")]
impl Hasher for Xxh3Wrapper {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.digest().to_le_bytes().to_vec()
    }

    fn output_size(&self) -> usize {
        8 // 64 bits
    }
}

/// Streaming XXH3-128 implementation used by the compatibility registry.
#[cfg(feature = "xxhash")]
pub struct Xxh128Wrapper(pub(crate) Xxh3HasherBase);

#[cfg(feature = "xxhash")]
impl Hasher for Xxh128Wrapper {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.digest128().to_le_bytes().to_vec()
    }

    fn output_size(&self) -> usize {
        16 // 128 bits
    }
}

/// A collection of streaming hashers updated from the same byte stream.
pub struct HasherSet {
    hashers: Vec<(Algorithm, Box<dyn Hasher>)>,
}

impl HasherSet {
    /// Construct one streaming hasher for each requested algorithm.
    ///
    /// Hashers and final results preserve the order of `algorithms`. Duplicate
    /// algorithms are permitted and produce duplicate results.
    pub fn new(algorithms: &[Algorithm]) -> Result<Self, HashUtilityError> {
        let mut hashers = Vec::with_capacity(algorithms.len());
        for &algorithm in algorithms {
            hashers.push((algorithm, algorithm.hasher()?));
        }
        Ok(Self { hashers })
    }

    /// Feed the same byte chunk to every hasher in the set.
    pub fn update(&mut self, data: &[u8]) {
        for (_, hasher) in &mut self.hashers {
            hasher.update(data);
        }
    }

    /// Consume the set and return its digests in requested order.
    pub fn finalize(self) -> Vec<DigestValue> {
        self.hashers
            .into_iter()
            .map(|(algorithm, hasher)| DigestValue {
                algorithm,
                bytes: hasher.finalize(),
            })
            .collect()
    }
}

/// Convert bytes to hexadecimal string
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
