# `quichash-core`

`quichash-core` is the reusable engine behind the QuicHash command-line
application. It hashes bytes, readers, files, and directory trees without
parsing command-line arguments or owning terminal output.

The typed API built around [`Algorithm`], [`DigestValue`], [`HasherSet`],
[`Manifest`], `scan_folder`, and `verify_folder` is recommended for new
applications. The engine types in the individual modules remain available for
compatibility with the QuicHash CLI.

## Dependency

Use the complete default configuration:

```toml
[dependencies]
quichash-core = "0.0.21"
```

When consuming the workspace directly:

```toml
[dependencies]
quichash-core = { path = "../hash-rs/crates/quichash-core" }
```

For a small BLAKE3-only build that hashes bytes and streams:

```toml
[dependencies]
quichash-core = { version = "0.0.21", default-features = false, features = ["blake3"] }
```

## Cargo features

The default feature set enables every feature below.

| Feature | Enables |
| --- | --- |
| `all-algorithms` | All algorithm features listed below |
| `md5` | MD5 |
| `sha1` | SHA-1 |
| `sha2` | SHA-224, SHA-256, SHA-384, and SHA-512 |
| `sha3` | SHA3-224, SHA3-256, SHA3-384, and SHA3-512 |
| `blake2` | BLAKE2b-512 and BLAKE2s-256 |
| `blake3` | BLAKE3 |
| `xxhash` | XXH3-64 and XXH3-128 |
| `filesystem` | Folder scanning, verification, ignore files, deduplication, and wildcard expansion |
| `parallel` | Rayon-powered folder work and BLAKE3 parallel support |
| `mmap` | Memory-mapped BLAKE3 file hashing |
| `xz` | Reading and creating XZ-compressed manifest files |
| `reporting` | JSON and timestamp support used by analysis and comparison reports |

Calling an algorithm that was compiled out returns
[`HashUtilityError::AlgorithmUnavailable`]. [`Algorithm::is_available`] and
[`HashRegistry::list_algorithms`](hash::HashRegistry::list_algorithms) can be
used to discover the compiled algorithms at runtime.

## Algorithms

[`Algorithm`] provides stable identifiers, parsing, display names, output
sizes, and feature availability for:

- MD5 and SHA-1
- SHA-224, SHA-256, SHA-384, and SHA-512
- SHA3-224, SHA3-256, SHA3-384, and SHA3-512
- BLAKE2b-512, BLAKE2s-256, and BLAKE3
- XXH3-64 (`xxh3`) and XXH3-128 (`xxh128`)

MD5, SHA-1, and xxHash are useful for compatibility or non-adversarial file
identification, but should not be selected for new security-sensitive uses.
BLAKE3 and SHA-2/3 are the usual choices for integrity verification.

## Hash bytes

Use [`hash_bytes`] for an in-memory value. Multiple algorithms consume the
input in one pass and results retain the requested order.

```
use quichash_core::{hash_bytes, Algorithm};

let digests = hash_bytes(b"hello", &[Algorithm::Blake3, Algorithm::Sha256])?;
assert_eq!(digests.len(), 2);
assert_eq!(digests[0].algorithm, Algorithm::Blake3);
assert_eq!(digests[0].to_hex().len(), 64);
# Ok::<(), quichash_core::HashUtilityError>(())
```

[`DigestValue::from_hex`] validates both hexadecimal syntax and the expected
length for its algorithm. [`DigestValue::as_bytes`] exposes the validated raw
digest when binary storage or comparison is preferable.

## Incremental hashing

Use [`HasherSet`] when an application already receives chunks, such as from a
network stream or archive decoder.

```
use quichash_core::{Algorithm, HasherSet};

let mut hashers = HasherSet::new(&[Algorithm::Blake3, Algorithm::Sha512])?;
hashers.update(b"first chunk");
hashers.update(b"second chunk");
let digests = hashers.finalize();
assert_eq!(digests.len(), 2);
# Ok::<(), quichash_core::HashUtilityError>(())
```

`HasherSet` is synchronous and has no async-runtime dependency. An async
application can update it with each buffer it reads, or move file work to its
runtime's blocking worker pool.

## Hash readers and files

[`hash_reader`] streams any [`std::io::Read`] implementation through all
requested algorithms with a 1 MiB internal buffer:

```
use std::io::Cursor;
use quichash_core::{hash_reader, Algorithm};

let mut reader = Cursor::new(b"reader input");
let digests = hash_reader(&mut reader, &[Algorithm::Blake3])?;
assert_eq!(digests.len(), 1);
# Ok::<(), quichash_core::HashUtilityError>(())
```

[`hash_file`] hashes an entire file. With `blake3`, `parallel`, and `mmap`
enabled, a single BLAKE3 file hash uses the optimized memory-mapped path when
possible. [`hash_file_mode`] additionally accepts [`HashMode`].

```no_run
use std::path::Path;
use quichash_core::{hash_file, Algorithm};

let digests = hash_file(Path::new("archive.tar"), &[Algorithm::Blake3])?;
println!("{}", digests[0].to_hex());
# Ok::<(), quichash_core::HashUtilityError>(())
```

[`HashMode::Full`] reads the complete file and is required for cryptographic
integrity. [`HashMode::Sampled`] hashes selected regions of large files for
quick identification; it is intentionally a different digest domain and must
not be treated as a complete integrity check.

## Progress and cancellation

Long-running typed APIs accept an [`OperationObserver`]. Its callbacks may be
invoked from worker threads, so implementations must be `Send + Sync` and
should return quickly. Cancellation is cooperative and returns
[`HashUtilityError::Cancelled`]. Use [`NoopObserver`] when neither capability
is needed.

```
use std::sync::atomic::{AtomicBool, Ordering};
use quichash_core::{OperationObserver, ProgressEvent};

#[derive(Default)]
struct Observer {
    cancelled: AtomicBool,
}

impl OperationObserver for Observer {
    fn on_progress(&self, event: &ProgressEvent) {
        let _completed = event.completed;
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}
```

[`hash_reader_observed`] reports streamed bytes. `scan_folder` reports file
discovery and hashing, and `verify_folder` reports verification progress.

## Scan a folder

Folder APIs require the `filesystem` feature. `scan_folder` recursively
hashes regular files, does not follow symbolic links, includes hidden files,
and optionally applies `.hashignore` patterns. Paths stored in the manifest are
relative to the supplied root.

```no_run
use std::path::Path;
use quichash_core::{
    scan_folder, Algorithm, FailurePolicy, HashMode, NoopObserver, ScanOptions,
};

let options = ScanOptions {
    algorithms: vec![Algorithm::Blake3, Algorithm::Sha256],
    mode: HashMode::Full,
    parallel: true,
    use_hashignore: true,
    failure_policy: FailurePolicy::FailFast,
    exclude: None,
};
let report = scan_folder(Path::new("assets"), &options, &NoopObserver)?;
println!("hashed {} files", report.files_processed);
for root in report.folder_digests {
    println!("{} {}", root.algorithm, root.digest.to_hex());
}
# Ok::<(), quichash_core::HashUtilityError>(())
```

Only regular files contribute to a folder digest. The digest commits to the
canonical relative path, size, hash mode, algorithm names, and every stored
file digest. Entry order does not affect it; renaming a file, changing modes,
or changing any digest does. The domain-separated encoding is versioned as
`quichash-folder-v1`.

`ScanOptions::exclude` omits one canonicalized file, which is useful when the
manifest is written inside the directory being scanned.

## Manifest formats

[`Manifest`] is the typed in-memory representation. Each [`ManifestEntry`]
contains a relative path, size, hash mode, and one or more validated digests.
Call [`Manifest::canonicalize`] before custom serialization, or
[`Manifest::folder_digests`] to derive tree hashes.

[`database::DatabaseHandler`] reads and writes:

- **Standard:** one `hash  algorithm  mode  path` row per digest. Repeated rows
  for the same path are merged into one multi-digest entry.
- **hashdeep:** `size,hash1,hash2,...,filename`, preserving every algorithm
  column declared by the header.
- **XZ:** either text format can be read transparently from an `.xz` path when
  `xz` is enabled. `compress_database` creates the compressed copy.

```no_run
use std::fs::File;
use std::path::Path;
use quichash_core::database::{DatabaseFormat, DatabaseHandler};

let manifest = DatabaseHandler::read_manifest(Path::new("hashes.txt"))?;
let mut output = File::create("hashes.hashdeep")?;
DatabaseHandler::write_manifest(&mut output, &manifest, DatabaseFormat::Hashdeep)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

[`DatabaseHandler::read_manifest`](database::DatabaseHandler::read_manifest)
is fail-fast. Use
[`DatabaseHandler::read_manifest_with_policy`](database::DatabaseHandler::read_manifest_with_policy)
with [`FailurePolicy::Continue`] to receive valid entries plus line-level
[`database::DatabaseIssue`] values.

JSON is available for analysis, comparison, and deduplication reports when the
`reporting` feature is enabled; it is not a persisted `Manifest` input format.

## Verify a folder

`verify_folder` recomputes every digest stored for every expected file. A
file counts as a match only when all its stored digests match. The report keeps
algorithm-specific mismatches, missing paths, new regular files, and recoverable
issues separate.

```no_run
use std::path::Path;
use quichash_core::{verify_folder, FailurePolicy, NoopObserver};
use quichash_core::database::DatabaseHandler;

let manifest = DatabaseHandler::read_manifest(Path::new("hashes.hashdeep"))?;
let report = verify_folder(
    &manifest,
    Path::new("assets"),
    FailurePolicy::FailFast,
    &NoopObserver,
)?;
let valid = report.mismatches.is_empty()
    && report.missing_files.is_empty()
    && report.new_files.is_empty()
    && report.issues.is_empty();
assert!(valid, "folder contents changed");
# Ok::<(), quichash_core::HashUtilityError>(())
```

[`FailurePolicy::FailFast`] returns the first operational or parsing error.
[`FailurePolicy::Continue`] retains item-level errors in the corresponding
report, but cancellation still stops immediately.

## Analysis, comparison, and deduplication

Compatibility engine modules expose the remaining QuicHash functionality:

- [`analyze::AnalyzeEngine`] summarizes a manifest and identifies duplicate
  digest groups.
- [`compare::CompareEngine`] compares two databases and reports unchanged,
  changed, moved, removed, added, and duplicate files.
- `dedup::DedupEngine` scans a directory and groups duplicate files. It
  reports candidates only and never deletes data.
- [`benchmark::BenchmarkEngine`] measures algorithm throughput.
- `wildcard::expand_pattern` expands CLI-style filesystem patterns.
- [`path_utils`] contains cross-platform normalization and relative-path
  helpers.

The older [`hash::HashComputer`], `scan::ScanEngine`, and
`verify::VerifyEngine` accept string algorithm names and mirror historical
CLI behavior. New embedded applications should prefer the typed functions at
the crate root because they provide validated digests, multi-hash manifests,
structured progress, and explicit error policy.

## Error handling

All primary operations return [`HashUtilityError`], which preserves the path
and operation where possible. Match the variants when recovery differs, or
display the error for a contextual message.

```
use quichash_core::{Algorithm, HashUtilityError};

let result = "not-an-algorithm".parse::<Algorithm>();
assert!(matches!(
    result,
    Err(HashUtilityError::UnsupportedAlgorithm { .. })
));
```

The library never starts an async runtime, performs network requests, or
parses process arguments. The typed APIs do not render progress; presentation
belongs to the embedding CLI, GUI, service, or application.
