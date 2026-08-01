# QuicHash

High-performance cryptographic hash utility with SIMD optimization.

The repository is a Cargo workspace containing the reusable `quichash-core`
library and the `quichash` CLI package, which installs the `hash` executable.

## Features

- **Algorithms**: MD5, SHA-1, SHA-2/3, BLAKE2/3, xxHash3/128
- **Defaults**: BLAKE3 algorithm, parallel processing
- **HDD Mode**: Sequential processing with `--hdd` flag for old mechanical drives
- **SIMD**: Automatic hardware acceleration (SSE, AVX, AVX2, AVX-512, NEON)
- **Optional Fast Mode**: Quick hashing for large files (samples 300MB) ONLY for edge cases
- **Flexible Input**: Files, stdin, or text strings
- **Wildcard Patterns**: Support for `*`, `?`, and `[...]` patterns in file/directory arguments
- **Directory Scanning**: Recursive hashing with parallel processing by default
- **Verification**: Compare hashes against stored database
- **Database Comparison**: Compare two databases to identify changes, moves, and differences
- **Database Analysis**: Analyze database statistics, duplicates, and potential space savings
- **Deduplication**: Find and report duplicate files based on hash comparison
- **.hashignore**: Exclude files using gitignore-style patterns
- **Formats**: Standard, hashdeep, JSON
- **Compression**: LZMA compression for databases
- **Cross-Platform**: Linux, macOS, Windows, FreeBSD

## Installation

```bash
cargo install quichash
```

Or build from source:

```bash
cargo build --release
```

## Library

Applications should depend on `quichash-core` rather than copying its source.
The default feature set includes all algorithms, folder operations, parallel
processing, memory mapping, and XZ manifests. A small BLAKE3-only build can use
`default-features = false, features = ["blake3"]`.

```rust
use quichash_core::{Algorithm, HasherSet};

let mut hashers = HasherSet::new(&[Algorithm::Blake3, Algorithm::Sha256])?;
hashers.update(b"first chunk");
hashers.update(b"second chunk");
let digests = hashers.finalize();
# Ok::<(), quichash_core::HashUtilityError>(())
```

For local trees, `scan_folder` returns a sorted multi-algorithm manifest plus
deterministic folder digests. `verify_folder` verifies every stored digest.
Both accept an `OperationObserver` for application-owned progress and
cooperative cancellation.

See the [complete `quichash-core` guide](crates/quichash-core/README.md) for the
algorithm and feature matrix, byte/stream/file hashing, folder manifests,
formats, verification, progress, cancellation, errors, and compatibility APIs.

## Quick Start

```bash
# Hash a file (uses blake3 by default)
hash myfile.txt

# Hash text
hash --text "hello world"

# Hash from stdin
cat myfile.txt | hash

# Scan directory (parallel by default)
hash scan -d ./my_dir -b hashes.db

# Scan on old HDD (sequential)
hash scan -d ./my_dir -b hashes.db --hdd

# Verify
hash verify -b hashes.db -d ./my_dir

# Analyze database
hash analyze -d hashes.db

# List algorithms
hash list
```

## Usage

### Hash Files

```bash
hash myfile.txt                              # Uses blake3 by default
hash myfile.txt -a sha256                    # Specify algorithm
hash myfile.txt -a sha256 -a blake3          # Multiple algorithms
hash largefile.iso -f                        # Fast mode
hash myfile.txt -b output.txt                # Save to file
hash myfile.txt --json                       # JSON output
```

### Wildcard Patterns

Hash multiple files using wildcard patterns:

```bash
hash "*.txt" -a sha256                       # All .txt files
hash "file?.bin" -a sha256                   # file1.bin, fileA.bin, etc.
hash "[abc]*.jpg" -a sha256                  # Files starting with a, b, or c
hash "img202405*.jpg" -a sha256              # All images from May 2024
```

Patterns work with all commands:

```bash
hash scan -d "data/*/hashes" -a sha256 -b output.db    # Multiple directories
hash verify -b "*.db" -d "data/*" --json               # Multiple databases/dirs
```

### Hash Text or Stdin

```bash
hash --text "hello world" -a sha256          # Hash text
cat myfile.txt | hash -a sha256              # Hash from stdin
```

### Scan Directory

```bash
hash scan -d /path/to/dir -b hashes.db                        # Basic (blake3, parallel)
hash scan -d /path/to/dir -b hashes.db --hdd                  # Sequential for old HDDs
hash scan -d /path/to/dir -a sha256 -b hashes.db              # Custom algorithm
hash scan -d /path/to/dir -b hashes.db -f                     # Fast mode
hash scan -d /path/to/dir -b hashes.db -f --hdd               # Fast mode, sequential
hash scan -d /path/to/dir -b hashes.db --compress             # Compressed
hash scan -d /path/to/dir -b hashes.db --format hashdeep      # Hashdeep format
```

### Verify Directory

```bash
hash verify -b hashes.db -d /path/to/dir                      # Parallel (default)
hash verify -b hashes.db -d /path/to/dir --hdd                # Sequential for old HDDs
hash verify -b hashes.db -d /path/to/dir --json               # JSON output
```

## Performance Optimizations

### Parallel Verification (Default)

The verification engine uses parallel processing by default for significantly faster verification:

```bash
# Parallel verification (default, 2-4x faster)
hash verify -b hashes.db -d /path/to/dir

# Sequential verification (for old HDDs)
hash verify -b hashes.db -d /path/to/dir --hdd
```

**Performance improvements:**
- **Parallel by default**: Uses all CPU cores via rayon (like scan)
- **Path canonicalization caching**: Reduces redundant filesystem calls
- **Optimized file collection**: Efficient recursive directory traversal
- **Reduced overhead**: Minimizes lock contention in parallel mode

**Parallel mode (default):**
- SSDs or NVMe drives (no seek penalty)
- Large numbers of files (>1000)
- Fast network storage
- Modern systems with multiple cores

**Sequential mode (--hdd flag):**
- Old mechanical HDDs (avoid thrashing)
- Network drives with high latency
- Systems with limited CPU cores
- When minimizing system load

```bash
hash verify -b hashes.db -d /path/to/dir              # Verify
hash verify -b hashes.db.xz -d /path/to/dir           # Compressed
hash verify -b hashes.db -d /path/to/dir --json       # JSON
```

Output shows: Matches, Mismatches, Missing files, New files

### Compare Databases

Compare two hash databases to identify changes, moves, and differences:

```bash
hash compare db1.txt db2.txt                          # Compare two databases
hash compare db1.txt db2.txt -b report.txt            # Save report to file
hash compare db1.txt db2.txt --format json            # JSON output
hash compare db1.txt db2.txt --format hashdeep        # Hashdeep audit format
hash compare db1.txt.xz db2.txt.xz                    # Compare compressed databases
hash compare db1.txt db2.txt.xz                       # Mix compressed and plain
```

Output shows:
- **Unchanged**: Files with same hash in both databases
- **Changed**: Files with different hashes
- **Moved**: Files renamed or moved (same hash, different path)
- **Removed**: Files in DB1 but not DB2
- **Added**: Files in DB2 but not DB1

### Analyze Database

Analyze a hash database to view statistics, duplicates, and potential space savings:

```bash
hash analyze -d hashes.db                             # Analyze database
hash analyze -d hashes.db --json                      # JSON output
hash analyze -d hashes.db -b report.txt               # Save report to file
hash analyze -d hashes.db.xz                          # Analyze compressed database
```

Output shows:
- **Database info**: Path, format (standard/hashdeep), size
- **Summary**: Total files, unique hashes, algorithms used
- **File sizes**: Total size of all files (hashdeep format only)
- **Duplicates**: Number of duplicate groups, duplicate files, potential space savings

### Deduplicate Files

Find and report duplicate files based on hash comparison:

```bash
hash dedup -d /path/to/dir                # Find duplicates (dry-run)
hash dedup -d /path/to/dir -b report.txt  # Save report to file
hash dedup -d /path/to/dir -f             # Fast mode
hash dedup -d /path/to/dir --json         # JSON output
```

Output shows duplicate groups with file paths and sizes.

### Benchmark & List

```bash
hash benchmark                    # Benchmark all algorithms
hash benchmark -s 500             # Custom data size
hash list                         # List algorithms
hash list --json                  # JSON output
```

## Command-Line Options

| Command | Option | Description |
|---------|--------|-------------|
| | `FILE` | File or wildcard pattern to hash (omit for stdin) |
| | `-t, --text <TEXT>` | Hash text string |
| | `-a, --algorithm <ALG>` | Algorithm (default: blake3) |
| | `-b, --output <FILE>` | Write to file |
| | `-f, --fast` | Fast mode (samples 300MB) |
| | `--json` | JSON output |
| scan | `-d, --directory <DIR>` | Directory or wildcard pattern to scan |
| | `-a, --algorithm <ALG>` | Algorithm (default: blake3) |
| | `-b, --database <FILE>` | Output database |
| | `--hdd` | Sequential mode for old HDDs (default: parallel) |
| | `-f, --fast` | Fast mode |
| | `--format <FMT>` | standard or hashdeep |
| | `--compress` | LZMA compression |
| | `--json` | JSON output |
| verify | `-b, --database <FILE>` | Database file or wildcard pattern |
| | `-d, --directory <DIR>` | Directory or wildcard pattern to verify |
| | `--json` | JSON output |
| compare | `DATABASE1` | First database file (supports .xz) |
| | `DATABASE2` | Second database file (supports .xz) |
| | `-b, --output <FILE>` | Write report to file |
| | `--format <FMT>` | plain-text, json, or hashdeep |
| analyze | `-d, --database <FILE>` | Database file to analyze (supports .xz) |
| | `-b, --output <FILE>` | Write report to file |
| | `--json` | JSON output |
| dedup | `-d, --directory <DIR>` | Directory to scan for duplicates |
| | `-f, --fast` | Fast mode |
| | `-b, --output <FILE>` | Write report to file |
| | `--json` | JSON output |
| benchmark | `-s, --size <MB>` | Data size (default: 100) |
| | `--json` | JSON output |

## .hashignore

Exclude files using gitignore-style patterns.

The pattern syntax is largely compatible with `.gitignore`, but `.hashignore`
is not a full reimplementation of Git's ignore behavior.

- QuicHash only reads `.hashignore`, not `.gitignore`, `.git/info/exclude`, or
  Git's global excludes.
- `scan` and `dedup` use `.hashignore`. `verify` currently does not.

For directory-scanning commands such as `scan` and `dedup`, QuicHash looks for
`.hashignore` in the directory you pass with `-d/--directory` and then in that
directory's parent directories. It does not use the current working directory
unless that is the scanned directory, it does not use the directory containing
the `hash` binary, and it does not look for additional `.hashignore` files in
subdirectories while walking the tree.

Example: if you scan `/path/to/dir`, QuicHash reads `/path/to/dir/.hashignore`
if present, then continues checking `/path/to/.hashignore`, `/path/.hashignore`,
and so on up the directory tree.

```bash
cat > /path/to/dir/.hashignore << 'EOF'
*.log
*.tmp
build/
node_modules/
!important.log
EOF

hash scan -d /path/to/dir -a sha256 -b hashes.db
```

Patterns: `*.ext`, `dir/`, `!pattern`, `#comments`, `**/*.ext`

## Output Formats

**Standard** (default):
```
<hash>  <algorithm>  <mode>  <filepath>
```

**Hashdeep**: CSV format with file size, compatible with hashdeep tool

**JSON**: Structured output for automation

## Performance

| Algorithm | Throughput | Use Case |
|-----------|-----------|----------|
| xxHash3 | 10-30 GB/s | Non-crypto, max speed |
| BLAKE3 | 1-3 GB/s | Crypto, fastest |
| SHA-512 | 600-900 MB/s | Crypto, 64-bit |
| SHA-256 | 500-800 MB/s | Crypto, common |
| SHA3-256 | 200-400 MB/s | Post-quantum |

**Tips:**
- Parallel processing is enabled by default (2-4x faster on multi-core)
- Use `--hdd` for old mechanical drives (sequential processing)
- Use `-f` for large files (10-100x faster)
- BLAKE3 is the default algorithm (fastest cryptographic hash)
- Compile with `RUSTFLAGS="-C target-cpu=native"` for best performance

**Fast Mode Speedup:**
- 1 GB: ~7x faster
- 10 GB: ~67x faster
- 100 GB: ~667x faster

## Fast Mode

Samples 300MB (first/middle/last 100MB) instead of entire file.

**Good for:** Quick checks, large files, backups
**Not for:** Full verification, forensics, small files

## Common Use Cases

```bash
# Verify downloaded file
hash downloaded-file.iso -a sha256

# Backup verification (parallel by default)
hash scan -d /data -b backup.db
hash verify -b backup.db -d /data

# Backup on old HDD (sequential processing)
hash scan -d /data -b backup.db --hdd
hash verify -b backup.db -d /data

# Monitor changes
hash scan -d /etc/config -b baseline.db
hash verify -b baseline.db -d /etc/config

# Compare two snapshots
hash scan -d /data -b snapshot1.db
# ... time passes ...
hash scan -d /data -b snapshot2.db
hash compare snapshot1.db snapshot2.db -b changes.txt

# Analyze database for duplicates and stats
hash analyze -d media.db                          # View stats and duplicates
hash analyze -d media.db --json                   # JSON output for automation

# Find duplicates in directory
hash dedup -d /media                              # Quick duplicate scan

# Forensic analysis
hash scan -d /evidence -a sha3-256 -b evidence.db
hash scan -d /evidence -a sha256 -b evidence.txt --format hashdeep

# Quick checksums (blake3 is default)
hash large-backup.tar.gz -f
hash scan -d /backups -b checksums.db -f

# Automation
hash verify -b hashes.db -d /data --json | jq '.report.mismatches'
hash compare db1.db db2.db --format json | jq '.summary'
```

## Algorithm Selection

**Recommended:**
- SHA-256: Widely supported, good security
- BLAKE3: Fastest cryptographic hash
- SHA3-256: Post-quantum resistant

**Deprecated:**
- MD5, SHA-1: Use only for compatibility

**Non-crypto (trusted environments):**
- xxHash3/128: Maximum speed

## SIMD Optimization

Automatic support for SSE, AVX, AVX2, AVX-512 (x86_64) and NEON (ARM).

Verify: `cargo test --release --test simd_verification -- --nocapture`

## Wildcard Patterns

Supported patterns:
- `*` - Matches any number of characters (e.g., `*.txt`, `file*`)
- `?` - Matches exactly one character (e.g., `file?.bin`)
- `[...]` - Matches any character in brackets (e.g., `[abc]*.jpg`)

**Examples:**
```bash
hash "*.txt" -a sha256                       # All .txt files in current dir
hash "data/*.bin" -a sha256                  # All .bin files in data/
hash "file?.txt" -a sha256                   # file1.txt, fileA.txt, etc.
hash "[abc]*.jpg" -a sha256                  # Files starting with a, b, or c
hash scan -d "backup/*/data" -a sha256 -b db.txt  # Multiple directories
hash verify -b "*.db" -d "data/*"            # All .db files against all data dirs
```

**Notes:**
- Patterns are expanded by the shell or the application
- If no files match, an error is displayed
- Multiple matches are processed in sorted order
- For scan/verify with multiple directories, results are aggregated

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Unsupported algorithm | Run `hash list` to see available algorithms |
| Permission errors | Use `sudo hash scan -d /protected/dir ...` |
| Slow performance | Use `-p` for parallel, `-f` for fast mode, or BLAKE3 |
| Fast mode not working | Fast mode only works with files (not stdin/text) |
| .hashignore not working | `scan` and `dedup` use `.hashignore`; put it in the scanned directory or one of its parent directories. Subdirectories are not searched for extra ignore files |
| Wildcard pattern not matching | Ensure pattern is quoted (e.g., `"*.txt"` not `*.txt`) |
| No files match pattern | Check pattern syntax and file locations |

## Contributing

We welcome contributions to QuicHash! To contribute, you must certify that you have the right to submit your contribution and agree to license it under the project's dual MIT/Apache-2.0 license.

#### Inbound = Outbound License

All contributions to QuicHash are made under the same dual MIT/Apache-2.0 license as the project itself.

## License

QuicHash is licensed under either:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT))

or

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
