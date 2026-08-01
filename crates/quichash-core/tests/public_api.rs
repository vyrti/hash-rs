use std::io::Cursor;

use quichash_core::{
    hash_bytes, hash_reader_observed, Algorithm, HashUtilityError, HasherSet, OperationObserver,
};

#[cfg(feature = "blake3")]
#[test]
fn incremental_and_one_shot_blake3_are_identical() {
    let input = b"a byte stream split across application-owned chunks";
    let expected = hash_bytes(input, &[Algorithm::Blake3]).unwrap();
    let mut hashers = HasherSet::new(&[Algorithm::Blake3]).unwrap();
    for chunk in input.chunks(7) {
        hashers.update(chunk);
    }
    assert_eq!(hashers.finalize(), expected);
}

#[cfg(feature = "blake3")]
#[test]
fn digest_hex_is_validated_and_round_trips() {
    let digest = hash_bytes(b"hello", &[Algorithm::Blake3])
        .unwrap()
        .remove(0);
    assert_eq!(
        quichash_core::DigestValue::from_hex(Algorithm::Blake3, &digest.to_hex()).unwrap(),
        digest,
    );
    assert!(quichash_core::DigestValue::from_hex(Algorithm::Blake3, "xyz").is_err());
}

struct Cancelled;

impl OperationObserver for Cancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

#[cfg(feature = "blake3")]
#[test]
fn reader_hashing_supports_cooperative_cancellation() {
    let result = hash_reader_observed(
        Cursor::new(vec![0_u8; 1024]),
        &[Algorithm::Blake3],
        &Cancelled,
    );
    assert!(matches!(result, Err(HashUtilityError::Cancelled)));
}

#[test]
fn registry_only_lists_compiled_algorithms() {
    assert_eq!(
        Algorithm::ALL
            .iter()
            .filter(|algorithm| algorithm.is_available())
            .count(),
        quichash_core::HashRegistry::list_algorithms().len(),
    );
}
