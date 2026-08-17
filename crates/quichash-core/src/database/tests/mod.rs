use super::*;
use crate::manifest::ManifestEntry;

fn sample_manifest() -> Manifest {
    Manifest {
        entries: vec![ManifestEntry {
            relative_path: PathBuf::from("nested/file.txt"),
            size: 0,
            mode: crate::hash::HashMode::Full,
            digests: vec![crate::hash::DigestValue {
                algorithm: Algorithm::Sha256,
                bytes: vec![2; 32],
            }],
        }],
    }
}

mod format_tests;
mod io_tests;
