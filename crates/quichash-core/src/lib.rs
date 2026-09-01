#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(unsafe_code)]

// Legacy engines historically rendered their own status. Keep their public
// compatibility methods quiet when embedded; the CLI owns presentation now.
macro_rules! println {
    () => {{}};
    ($($argument:tt)*) => {{ let _ = format_args!($($argument)*); }};
}
macro_rules! eprintln {
    () => {{}};
    ($($argument:tt)*) => {{ let _ = format_args!($($argument)*); }};
}

pub mod analyze;
pub mod benchmark;
pub mod compare;
pub mod database;
#[cfg(feature = "filesystem")]
pub mod dedup;
pub mod error;
pub mod hash;
#[cfg(feature = "filesystem")]
pub mod ignore_handler;
pub mod manifest;
pub mod operation;
pub mod path_utils;
#[cfg(feature = "filesystem")]
pub mod scan;
#[cfg(feature = "filesystem")]
pub mod verify;
#[cfg(feature = "filesystem")]
pub mod wildcard;

pub use error::HashUtilityError;
pub use hash::{
    Algorithm, AlgorithmInfo, DigestValue, HashComputer, HashMode, HashRegistry, HashResult,
    Hasher, HasherSet, hash_bytes, hash_file, hash_file_mode, hash_reader, hash_reader_observed,
};
#[cfg(feature = "filesystem")]
pub use manifest::{
    DigestMismatch, ManifestVerifyReport, OperationIssue, ScanOptions, ScanReport, scan_folder,
    verify_folder,
};
pub use manifest::{FolderDigest, Manifest, ManifestEntry};
pub use operation::{FailurePolicy, NoopObserver, OperationObserver, ProgressEvent, ProgressPhase};
