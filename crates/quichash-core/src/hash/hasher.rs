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

// Keeping states inline avoids one heap allocation per algorithm per file. The
// largest state determines the enum size, which is an intentional tradeoff for
// the tiny-file workload.
#[allow(clippy::large_enum_variant)]
enum HasherState {
    #[cfg(feature = "md5")]
    Md5(Md5),
    #[cfg(feature = "sha1")]
    Sha1(Sha1),
    #[cfg(feature = "sha2")]
    Sha224(Sha224),
    #[cfg(feature = "sha2")]
    Sha256(Sha256),
    #[cfg(feature = "sha2")]
    Sha384(Sha384),
    #[cfg(feature = "sha2")]
    Sha512(Sha512),
    #[cfg(feature = "sha3")]
    Sha3_224(Sha3_224),
    #[cfg(feature = "sha3")]
    Sha3_256(Sha3_256),
    #[cfg(feature = "sha3")]
    Sha3_384(Sha3_384),
    #[cfg(feature = "sha3")]
    Sha3_512(Sha3_512),
    #[cfg(feature = "blake2")]
    Blake2b512(Blake2b512),
    #[cfg(feature = "blake2")]
    Blake2s256(Blake2s256),
    #[cfg(feature = "blake3")]
    Blake3(Blake3Hasher),
    #[cfg(feature = "xxhash")]
    Xxh3(Xxh3Hasher),
    #[cfg(feature = "xxhash")]
    Xxh128(Xxh3HasherBase),
}

impl HasherState {
    fn new(algorithm: Algorithm) -> Result<Self, HashUtilityError> {
        #[allow(unreachable_patterns)]
        match algorithm {
            #[cfg(feature = "md5")]
            Algorithm::Md5 => Ok(Self::Md5(Md5::default())),
            #[cfg(feature = "sha1")]
            Algorithm::Sha1 => Ok(Self::Sha1(Sha1::default())),
            #[cfg(feature = "sha2")]
            Algorithm::Sha224 => Ok(Self::Sha224(Sha224::default())),
            #[cfg(feature = "sha2")]
            Algorithm::Sha256 => Ok(Self::Sha256(Sha256::default())),
            #[cfg(feature = "sha2")]
            Algorithm::Sha384 => Ok(Self::Sha384(Sha384::default())),
            #[cfg(feature = "sha2")]
            Algorithm::Sha512 => Ok(Self::Sha512(Sha512::default())),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_224 => Ok(Self::Sha3_224(Sha3_224::default())),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_256 => Ok(Self::Sha3_256(Sha3_256::default())),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_384 => Ok(Self::Sha3_384(Sha3_384::default())),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_512 => Ok(Self::Sha3_512(Sha3_512::default())),
            #[cfg(feature = "blake2")]
            Algorithm::Blake2b512 => Ok(Self::Blake2b512(Blake2b512::default())),
            #[cfg(feature = "blake2")]
            Algorithm::Blake2s256 => Ok(Self::Blake2s256(Blake2s256::default())),
            #[cfg(feature = "blake3")]
            Algorithm::Blake3 => Ok(Self::Blake3(Blake3Hasher::new())),
            #[cfg(feature = "xxhash")]
            Algorithm::Xxh3 => Ok(Self::Xxh3(Xxh3Hasher::new())),
            #[cfg(feature = "xxhash")]
            Algorithm::Xxh128 => Ok(Self::Xxh128(Xxh3HasherBase::new())),
            unavailable => Err(HashUtilityError::AlgorithmUnavailable {
                algorithm: unavailable.to_string(),
                feature: unavailable.required_feature(),
            }),
        }
    }

    fn update(&mut self, data: &[u8]) {
        let _ = data;
        #[allow(unreachable_patterns)]
        match self {
            #[cfg(feature = "md5")]
            Self::Md5(hasher) => Md5Digest::update(hasher, data),
            #[cfg(feature = "sha1")]
            Self::Sha1(hasher) => Sha1Digest::update(hasher, data),
            #[cfg(feature = "sha2")]
            Self::Sha224(hasher) => Sha2Digest::update(hasher, data),
            #[cfg(feature = "sha2")]
            Self::Sha256(hasher) => Sha2Digest::update(hasher, data),
            #[cfg(feature = "sha2")]
            Self::Sha384(hasher) => Sha2Digest::update(hasher, data),
            #[cfg(feature = "sha2")]
            Self::Sha512(hasher) => Sha2Digest::update(hasher, data),
            #[cfg(feature = "sha3")]
            Self::Sha3_224(hasher) => Sha3Digest::update(hasher, data),
            #[cfg(feature = "sha3")]
            Self::Sha3_256(hasher) => Sha3Digest::update(hasher, data),
            #[cfg(feature = "sha3")]
            Self::Sha3_384(hasher) => Sha3Digest::update(hasher, data),
            #[cfg(feature = "sha3")]
            Self::Sha3_512(hasher) => Sha3Digest::update(hasher, data),
            #[cfg(feature = "blake2")]
            Self::Blake2b512(hasher) => Blake2Digest::update(hasher, data),
            #[cfg(feature = "blake2")]
            Self::Blake2s256(hasher) => Blake2Digest::update(hasher, data),
            #[cfg(feature = "blake3")]
            Self::Blake3(hasher) => {
                hasher.update(data);
            }
            #[cfg(feature = "xxhash")]
            Self::Xxh3(hasher) | Self::Xxh128(hasher) => hasher.update(data),
            _ => unreachable!("an unavailable hasher cannot be constructed"),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            #[cfg(feature = "md5")]
            Self::Md5(hasher) => Md5Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "sha1")]
            Self::Sha1(hasher) => Sha1Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "sha2")]
            Self::Sha224(hasher) => Sha2Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "sha2")]
            Self::Sha256(hasher) => Sha2Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "sha2")]
            Self::Sha384(hasher) => Sha2Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "sha2")]
            Self::Sha512(hasher) => Sha2Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "sha3")]
            Self::Sha3_224(hasher) => Sha3Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "sha3")]
            Self::Sha3_256(hasher) => Sha3Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "sha3")]
            Self::Sha3_384(hasher) => Sha3Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "sha3")]
            Self::Sha3_512(hasher) => Sha3Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "blake2")]
            Self::Blake2b512(hasher) => Blake2Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "blake2")]
            Self::Blake2s256(hasher) => Blake2Digest::finalize(hasher).to_vec(),
            #[cfg(feature = "blake3")]
            Self::Blake3(hasher) => hasher.finalize().as_bytes().to_vec(),
            #[cfg(feature = "xxhash")]
            Self::Xxh3(hasher) => hasher.digest().to_le_bytes().to_vec(),
            #[cfg(feature = "xxhash")]
            Self::Xxh128(hasher) => hasher.digest128().to_le_bytes().to_vec(),
        }
    }
}

/// A collection of streaming hashers updated from the same byte stream.
pub struct HasherSet {
    hashers: Vec<(Algorithm, HasherState)>,
}

impl HasherSet {
    /// Construct one streaming hasher for each requested algorithm.
    ///
    /// Hashers and final results preserve the order of `algorithms`. Duplicate
    /// algorithms are permitted and produce duplicate results.
    pub fn new(algorithms: &[Algorithm]) -> Result<Self, HashUtilityError> {
        let mut hashers = Vec::with_capacity(algorithms.len());
        for &algorithm in algorithms {
            hashers.push((algorithm, HasherState::new(algorithm)?));
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
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
