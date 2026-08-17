//! Command-line parsing.
// Handles command-line argument parsing and validation

use clap::{Parser, Subcommand};
use quichash_core::error::HashUtilityError;
use std::path::PathBuf;

/// Hash Utility - Cryptographic hash computation and verification tool
///
/// A cross-platform console application for computing cryptographic hashes,
/// scanning directories, and verifying file integrity.
#[derive(Parser, Debug)]
#[command(name = "hash")]
#[command(version)]
#[command(about = "Cryptographic hash computation and verification tool", long_about = None)]
#[command(after_help = "EXAMPLES:\n  \
    hash file.txt                                           # uses blake3 by default\n  \
    hash file.txt -a sha256                                 # specify algorithm\n  \
    hash file.txt -f -a sha256                              # fast mode\n  \
    hash --text \"hello world\" -a sha256\n  \
    cat file.txt | hash -a sha256\n  \
    hash scan -d /path/to/dir -b hashes                    # creates hashes.qh\n  \
    hash scan -d /path/to/dir -b hashes --hdd              # sequential for old HDDs\n  \
    hash scan -d /path/to/dir -b hashes --format hashdeep  # creates hashes.hashdeep\n  \
    hash scan -d /path/to/dir -b hashes --compress         # creates hashes.qh.xz\n  \
    hash scan -d /path/to/dir -b hashes --json             # JSON report on stdout\n  \
    hash verify -b hashes.qh -d /path/to/dir               # parallel by default\n  \
    hash verify -b hashes.qh -d /path/to/dir --hdd         # sequential for old HDDs\n  \
    hash verify -b checks.sha256 -d /path/to/dir           # two-column checksum file\n  \
    hash compare db1.qh db2.qh                                # compare two databases\n  \
    hash compare db1.qh db2.qh -b report.txt --format json    # JSON output\n  \
    hash dedup -d /path/to/dir                              # find duplicates\n  \
    hash dedup -d /path/to/dir --fast --json                # fast mode with JSON output\n  \
    hash benchmark\n  \
    hash list")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// File or wildcard pattern to hash (e.g., *.txt, file?.bin, \[abc\]*.jpg)
    /// If omitted, reads from stdin for piping
    #[arg(value_name = "FILE")]
    pub file: Option<String>,

    /// Hash text string directly instead of a file (e.g., --text "hello world")
    #[arg(
        short = 't',
        long = "text",
        value_name = "TEXT",
        conflicts_with = "file"
    )]
    pub text: Option<String>,

    /// Hash algorithm to use: md5, sha1, sha256, sha512, sha3-256, blake2b, blake3, xxh3, etc. (use 'hash list' to see all)
    #[arg(
        short = 'a',
        long = "algorithm",
        value_name = "ALGORITHM",
        default_value = "blake3"
    )]
    pub algorithms: Vec<String>,

    /// Write output to file instead of stdout
    #[arg(short = 'b', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Fast mode: hash only first/middle/last 100MB of large files (faster but less thorough)
    #[arg(short = 'f', long = "fast")]
    pub fast: bool,

    /// Output results as JSON instead of plain text
    #[arg(long = "json")]
    pub json: bool,
}

/// Available commands
#[derive(Subcommand, Debug, PartialEq)]
pub enum Command {
    /// Scan directory and generate hash database
    ///
    /// Recursively scans a directory and computes hashes for all files,
    /// storing the results in a plain text database file.
    Scan {
        /// Directory or wildcard pattern to scan recursively (e.g., data/*/hashes)
        #[arg(short = 'd', long = "directory", value_name = "DIR")]
        directory: String,

        /// Hash algorithm to use (use 'hash list' to see all available algorithms)
        #[arg(
            short = 'a',
            long = "algorithm",
            value_name = "ALGORITHM",
            default_value = "blake3"
        )]
        algorithm: String,

        /// Database basename or path; the extension is normalized for the selected format
        #[arg(short = 'b', long = "database", value_name = "FILE")]
        database: PathBuf,

        /// Sequential mode for old HDDs (processes files one by one instead of parallel)
        #[arg(long = "hdd")]
        hdd: bool,

        /// Fast mode: hash only first/middle/last 100MB of large files (faster but less thorough)
        #[arg(short = 'f', long = "fast")]
        fast: bool,

        /// Output format: 'quichash' (native text) or 'hashdeep' (CSV)
        #[arg(long = "format", value_name = "FORMAT", default_value = "quichash")]
        format: String,

        /// Output results as JSON with metadata instead of plain text
        #[arg(long = "json")]
        json: bool,

        /// Compress QuicHash output with LZMA (creates a .qh.xz file)
        #[arg(long = "compress")]
        compress: bool,
    },

    /// Verify directory against hash database
    ///
    /// Compares current file hashes against a stored database to detect
    /// modifications, deletions, and new files.
    Verify {
        /// Hash database file or wildcard pattern (e.g., *.qh, hashes?.qh)
        /// Supports QuicHash, hashdeep, two-column checksum files, and compressed .xz formats
        #[arg(short = 'b', long = "database", value_name = "FILE")]
        database: String,

        /// Directory or wildcard pattern to verify (e.g., data/*, dir?)
        #[arg(short = 'd', long = "directory", value_name = "DIR")]
        directory: String,

        /// Sequential mode for old HDDs (processes files one by one instead of parallel)
        #[arg(long = "hdd")]
        hdd: bool,

        /// Output verification report as JSON instead of plain text
        #[arg(long = "json")]
        json: bool,
    },

    /// Benchmark hash algorithms
    ///
    /// Tests all supported hash algorithms and displays their throughput
    /// on the current hardware.
    Benchmark {
        /// Size of test data in megabytes (larger = more accurate, but slower)
        #[arg(short = 's', long = "size", value_name = "MB", default_value = "100")]
        size_mb: usize,

        /// Output benchmark results as JSON instead of formatted table
        #[arg(long = "json")]
        json: bool,
    },

    /// List available hash algorithms
    ///
    /// Displays all supported hash algorithms with their properties,
    /// including output size and post-quantum resistance status.
    List {
        /// Output algorithm list as JSON instead of formatted table
        #[arg(long = "json")]
        json: bool,
    },

    /// Compare two hash databases
    ///
    /// Compares two hash database files to identify unchanged files, changed files,
    /// moved files, removed files, and added files.
    /// Supports QuicHash, hashdeep, and compressed (.xz) database formats.
    Compare {
        /// First hash database file path (supports .xz compressed files)
        #[arg(value_name = "DATABASE1")]
        database1: PathBuf,

        /// Second hash database file path (supports .xz compressed files)
        #[arg(value_name = "DATABASE2")]
        database2: PathBuf,

        /// Write comparison report to file instead of stdout
        #[arg(short = 'b', long = "output", value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format: 'plain-text' (default), 'json', or 'hashdeep'
        #[arg(long = "format", value_name = "FORMAT", default_value = "plain-text")]
        format: String,
    },

    /// Display version information
    ///
    /// Shows the current version of the Hash Utility.
    Version,

    /// Find duplicate files in a directory
    ///
    /// Scans a directory recursively and identifies files with identical content
    /// by comparing their hash values. Always uses BLAKE3 algorithm for speed and security.
    Dedup {
        /// Directory to scan for duplicates
        #[arg(short = 'd', long = "directory", value_name = "DIR")]
        directory: PathBuf,

        /// Fast mode: hash only first/middle/last 100MB of large files (faster but less thorough)
        #[arg(short = 'f', long = "fast")]
        fast: bool,

        /// Write output to file instead of stdout
        #[arg(short = 'b', long = "output", value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output results as JSON instead of plain text
        #[arg(long = "json")]
        json: bool,
    },

    /// Analyze a hash database and display statistics
    ///
    /// Displays comprehensive statistics about a hash database file including
    /// file counts, duplicate detection, and potential space savings.
    /// File sizes are only available for hashdeep format databases.
    Analyze {
        /// Hash database file path (supports .xz compressed files)
        #[arg(short = 'd', long = "database", value_name = "FILE")]
        database: PathBuf,

        /// Output results as JSON instead of plain text
        #[arg(long = "json")]
        json: bool,

        /// Write output to file instead of stdout
        #[arg(short = 'b', long = "output", value_name = "FILE")]
        output: Option<PathBuf>,
    },
}

/// Parse command-line arguments
///
/// # Returns
/// Parsed CLI structure containing the command and its arguments
///
/// # Errors
/// Returns an error if arguments are invalid or missing required values
pub fn parse_args() -> Result<Cli, HashUtilityError> {
    match Cli::try_parse() {
        Ok(cli) => Ok(cli),
        Err(e) => {
            // Check if this is a help or version request (which clap treats as "errors")
            // These should be printed and exit successfully
            if e.kind() == clap::error::ErrorKind::DisplayHelp
                || e.kind() == clap::error::ErrorKind::DisplayVersion
            {
                // Print the help/version message and exit successfully
                print!("{}", e);
                std::process::exit(0);
            }

            // For actual errors, return our custom error type
            Err(HashUtilityError::InvalidArguments {
                message: e.to_string(),
            })
        }
    }
}
