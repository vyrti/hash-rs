use quichash_core::hash::{Algorithm, DigestValue, HashRegistry};
use std::str::FromStr;

#[test]
fn test_all_algorithms_properties() {
    for algo in Algorithm::ALL {
        assert!(!algo.canonical_name().is_empty());
        assert!(!algo.display_name().is_empty());
        assert!(algo.output_size() > 0);
        assert!(!algo.required_feature().is_empty());

        let parsed = Algorithm::from_str(algo.canonical_name()).unwrap();
        assert_eq!(parsed, algo);

        let parsed_display = Algorithm::from_str(algo.display_name()).unwrap();
        assert_eq!(parsed_display, algo);

        if algo.is_available() {
            let hasher = HashRegistry::get_hasher(algo.canonical_name());
            assert!(hasher.is_ok());
        }
    }

    assert!(Algorithm::from_str("nonexistent_algo").is_err());
}

#[test]
fn test_digest_value_round_trips() {
    for algo in Algorithm::ALL {
        let dummy_bytes = vec![7u8; algo.output_size()];
        let digest = DigestValue::from_bytes(algo, dummy_bytes.clone()).unwrap();

        assert_eq!(digest.algorithm, algo);
        assert_eq!(digest.as_bytes(), &dummy_bytes[..]);

        let hex = digest.to_hex();
        assert_eq!(hex.len(), algo.output_size() * 2);

        let from_hex = DigestValue::from_hex(algo, &hex).unwrap();
        assert_eq!(from_hex, digest);

        // Invalid byte lengths
        let too_short = vec![7u8; algo.output_size() - 1];
        assert!(DigestValue::from_bytes(algo, too_short).is_err());

        let too_long = vec![7u8; algo.output_size() + 1];
        assert!(DigestValue::from_bytes(algo, too_long).is_err());
    }
}
