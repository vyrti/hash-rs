# QuicHash CLI

High-performance cryptographic hash utility with SIMD optimization. Installs the `hash` executable.

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
- **Formats**: QuicHash (`.qh`), hashdeep (`.hashdeep`), two-column checksum verification, JSON reports
- **Compression**: Zstandard compression for QuicHash databases (`.qh.zst`)
- **Cross-Platform**: Linux, macOS, Windows, FreeBSD

## Installation

```bash
cargo install quichash
```

## Quick Start

```bash
# Hash a file (uses blake3 by default)
hash myfile.txt

# Hash text
hash --text "hello world"

# Hash from stdin
cat myfile.txt | hash

# Scan directory (parallel by default)
hash scan -d ./my_dir -b hashes       # creates hashes.qh

# Scan on old HDD (sequential)
hash scan -d ./my_dir -b hashes --hdd

# Verify
hash verify -b hashes.qh -d ./my_dir

# Verify a conventional checksum file (algorithm inferred from extension)
hash verify -b checks.sha256 -d ./my_dir

# Analyze database
hash analyze -d hashes.qh

# List algorithms
hash list
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
| | `--format <FMT>` | quichash (default) or hashdeep |
| | `--compress` | Zstandard compression; QuicHash only |
| | `--json` | JSON output |
| verify | `-b, --database <FILE>` | Database file or wildcard pattern |
| | `-d, --directory <DIR>` | Directory or wildcard pattern to verify |
| | `--json` | JSON output |
| compare | `DATABASE1` | First database file (supports .zst) |
| | `DATABASE2` | Second database file (supports .zst) |
| | `-b, --output <FILE>` | Write report to file |
| | `--format <FMT>` | plain-text, json, or hashdeep |
| analyze | `-d, --database <FILE>` | Database file to analyze (supports .zst) |
| | `-b, --output <FILE>` | Write report to file |
| | `--json` | JSON output |
| dedup | `-d, --directory <DIR>` | Directory to scan for duplicates |
| | `-f, --fast` | Fast mode |
| | `-b, --output <FILE>` | Write report to file |
| | `--json` | JSON output |
| benchmark | `-s, --size <MB>` | Data size (default: 100) |
| | `--json` | JSON output |

## License

Dual-licensed under MIT or Apache-2.0.
