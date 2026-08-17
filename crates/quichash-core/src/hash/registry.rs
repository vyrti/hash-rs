use std::str::FromStr;

use super::algorithm::{Algorithm, AlgorithmInfo};
use super::hasher::*;
use crate::error::HashUtilityError;

/// Registry for hash algorithms
pub struct HashRegistry;

impl HashRegistry {
    /// Get a hasher instance for the specified algorithm
    pub fn get_hasher(algorithm: &str) -> Result<Box<dyn Hasher>, HashUtilityError> {
        let parsed = Algorithm::from_str(algorithm)?;
        if !parsed.is_available() {
            return Err(HashUtilityError::AlgorithmUnavailable {
                algorithm: parsed.to_string(),
                feature: parsed.required_feature(),
            });
        }
        #[allow(unreachable_patterns)]
        match parsed {
            #[cfg(feature = "md5")]
            Algorithm::Md5 => Ok(Box::new(Md5Wrapper(md5::Md5::default()))),
            #[cfg(feature = "sha1")]
            Algorithm::Sha1 => Ok(Box::new(Sha1Wrapper(sha1::Sha1::default()))),
            #[cfg(feature = "sha2")]
            Algorithm::Sha224 => Ok(Box::new(Sha224Wrapper(sha2::Sha224::default()))),
            #[cfg(feature = "sha2")]
            Algorithm::Sha256 => Ok(Box::new(Sha256Wrapper(sha2::Sha256::default()))),
            #[cfg(feature = "sha2")]
            Algorithm::Sha384 => Ok(Box::new(Sha384Wrapper(sha2::Sha384::default()))),
            #[cfg(feature = "sha2")]
            Algorithm::Sha512 => Ok(Box::new(Sha512Wrapper(sha2::Sha512::default()))),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_224 => Ok(Box::new(Sha3_224Wrapper(sha3::Sha3_224::default()))),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_256 => Ok(Box::new(Sha3_256Wrapper(sha3::Sha3_256::default()))),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_384 => Ok(Box::new(Sha3_384Wrapper(sha3::Sha3_384::default()))),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_512 => Ok(Box::new(Sha3_512Wrapper(sha3::Sha3_512::default()))),
            #[cfg(feature = "blake2")]
            Algorithm::Blake2b512 => Ok(Box::new(Blake2b512Wrapper(blake2::Blake2b512::default()))),
            #[cfg(feature = "blake2")]
            Algorithm::Blake2s256 => Ok(Box::new(Blake2s256Wrapper(blake2::Blake2s256::default()))),
            #[cfg(feature = "blake3")]
            Algorithm::Blake3 => Ok(Box::new(Blake3Wrapper(blake3::Hasher::new()))),
            #[cfg(feature = "xxhash")]
            Algorithm::Xxh3 => Ok(Box::new(Xxh3Wrapper(xxhash_rust::xxh3::Xxh3::new()))),
            #[cfg(feature = "xxhash")]
            Algorithm::Xxh128 => Ok(Box::new(Xxh128Wrapper(xxhash_rust::xxh3::Xxh3::new()))),
            unavailable => Err(HashUtilityError::AlgorithmUnavailable {
                algorithm: unavailable.to_string(),
                feature: unavailable.required_feature(),
            }),
        }
    }

    /// List all available hash algorithms
    pub fn list_algorithms() -> Vec<AlgorithmInfo> {
        Algorithm::ALL
            .into_iter()
            .filter(|algorithm| algorithm.is_available())
            .map(|algorithm| AlgorithmInfo {
                name: algorithm.display_name().to_owned(),
                output_bits: algorithm.output_size() * 8,
                post_quantum: matches!(
                    algorithm,
                    Algorithm::Sha3_224
                        | Algorithm::Sha3_256
                        | Algorithm::Sha3_384
                        | Algorithm::Sha3_512
                ),
                cryptographic: !matches!(algorithm, Algorithm::Xxh3 | Algorithm::Xxh128),
            })
            .collect()
    }

    /// Check if an algorithm is post-quantum resistant
    pub fn is_post_quantum(algorithm: &str) -> bool {
        let alg_lower = algorithm.to_lowercase();

        // SHA-3 family algorithms are considered post-quantum resistant
        alg_lower.starts_with("sha3-") || alg_lower == "shake128" || alg_lower == "shake256"
    }
}
