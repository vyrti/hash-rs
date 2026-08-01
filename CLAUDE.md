# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

QuicHash (quichash) is a Rust command-line application for cryptographic hash computation. It supports multiple algorithms (MD5, SHA-1/2/3, BLAKE2/3, xxHash3/128), parallel processing, and various database formats.

## Build Commands

```bash
# Build
cargo build --workspace             # Debug build

# Testing
cargo test --workspace --all-features # Run all tests
cargo test <test_name>               # Run single test

# Run
cargo run -p quichash -- <args>      # Run CLI
```

## Architecture

### Workspace Structure

- `crates/quichash-core` owns reusable hashing, manifests, formats, and engines.
- `crates/quichash-cli` owns Clap parsing, terminal rendering, and the `hash` binary.

### Module Structure

| Module | Responsibility |
|--------|----------------|
| `main.rs` | Entry point, command dispatcher, stdin/terminal detection |
| `cli.rs` | Clap-based argument parsing, command definitions |
| `hash.rs` | Hash algorithm registry, `Hasher` trait for pluggable algorithms |
| `scan.rs` | Parallel directory traversal (rayon), progress bars, .hashignore support |
| `verify.rs` | Hash comparison against stored database, report generation |
| `compare.rs` | Two-database comparison, change detection |
| `dedup.rs` | Duplicate file detection by hash |
| `benchmark.rs` | Algorithm performance testing |
| `database.rs` | Plain-text and hashdeep format parsing/writing, LZMA compression |
| `error.rs` | Centralized error types with context (file paths, operations) |
| `path_utils.rs` | Path canonicalization with caching |
| `ignore_handler.rs` | gitignore-style pattern matching for file exclusion |
| `wildcard.rs` | Wildcard pattern expansion (`*`, `?`, `[...]`) |

### Key Patterns

- **Trait-Based Hash Abstraction:** New algorithms implement the `Hasher` trait in `hash.rs`
- **Builder Pattern:** `ScanEngine`, `VerifyEngine` use chainable configuration
- **Error Context:** Rich error types in `error.rs` include paths and operations
- **Parallel Processing:** rayon for CPU-intensive operations, jwalk for directory traversal
- **Progress Tracking:** indicatif for user feedback on long operations

### Commands

1. **Hash** - Compute hash(es) for files, text, or stdin
2. **Scan** - Recursively hash directories, generate databases
3. **Verify** - Compare directory against stored hashes
4. **Compare** - Compare two hash databases
5. **Dedup** - Find duplicate files by hash
6. **Benchmark** - Performance test all algorithms
7. **List** - List available algorithms

### Database Formats

- Standard text: `<hash>  <algorithm>  <mode>  <filepath>`
- Hashdeep CSV format (compatible with hashdeep tool)
- JSON output for automation
- LZMA compression (.xz) supported

## Key Dependencies

- **clap 4.5** - CLI parsing with derive macros
- **blake3, sha1, sha2, sha3, blake2, md-5** - Hash implementations
- **xxhash-rust** - Non-cryptographic hashing
- **rayon** - Data parallelism
- **indicatif** - Progress bars
- **jwalk** - Parallel directory traversal
- **memmap2** - Memory-mapped file I/O
- **xz2** - LZMA compression

## CI/CD

GitHub Actions runs on push/PR:
- Matrix builds: Linux, Windows, macOS
- Tests run on all platforms
- Releases build 9 target configurations including cross-compilation
