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

    /// File or wildcard pattern to hash (e.g., *.txt, file?.bin, [abc]*.jpg)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hash_command() {
        let args = vec!["hash", "test.txt", "-a", "sha256"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, Some("test.txt".to_string()));
        assert_eq!(cli.algorithms, vec!["sha256"]);
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, false);
        assert_eq!(cli.json, false);
    }

    #[test]
    fn test_parse_hash_command_multiple_algorithms() {
        let args = vec!["hash", "test.txt", "-a", "sha256", "-a", "md5"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, Some("test.txt".to_string()));
        assert_eq!(cli.algorithms, vec!["sha256", "md5"]);
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, false);
    }

    #[test]
    fn test_parse_hash_command_with_output() {
        let args = vec!["hash", "test.txt", "-a", "sha256", "-b", "output.txt"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, Some("test.txt".to_string()));
        assert_eq!(cli.algorithms, vec!["sha256"]);
        assert_eq!(cli.output, Some(PathBuf::from("output.txt")));
        assert_eq!(cli.fast, false);
    }

    #[test]
    fn test_parse_hash_command_long_flags() {
        let args = vec!["hash", "test.txt", "--algorithm", "sha256"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, Some("test.txt".to_string()));
        assert_eq!(cli.algorithms, vec!["sha256"]);
        assert_eq!(cli.fast, false);
    }

    #[test]
    fn test_parse_hash_command_with_fast_mode() {
        let args = vec!["hash", "test.txt", "-a", "sha256", "-f"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, Some("test.txt".to_string()));
        assert_eq!(cli.algorithms, vec!["sha256"]);
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, true);
    }

    #[test]
    fn test_parse_hash_command_with_fast_mode_long_flag() {
        let args = vec!["hash", "test.txt", "--fast"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, Some("test.txt".to_string()));
        assert_eq!(cli.algorithms, vec!["blake3"]); // default
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, true);
    }

    #[test]
    fn test_parse_hash_command_with_fast_and_multiple_algorithms() {
        let args = vec!["hash", "test.txt", "-a", "sha256", "-a", "md5", "-f"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, Some("test.txt".to_string()));
        assert_eq!(cli.algorithms, vec!["sha256", "md5"]);
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, true);
    }

    #[test]
    fn test_parse_scan_command() {
        let args = vec![
            "hash",
            "scan",
            "-d",
            "/path/to/dir",
            "-a",
            "sha256",
            "-b",
            "hashes.txt",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Scan {
                directory,
                algorithm,
                database,
                hdd,
                fast,
                format,
                json,
                compress,
            }) => {
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(algorithm, "sha256");
                assert_eq!(database, PathBuf::from("hashes.txt"));
                assert_eq!(hdd, false);
                assert_eq!(fast, false);
                assert_eq!(format, "quichash");
                assert_eq!(json, false);
                assert_eq!(compress, false);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_scan_command_with_hdd() {
        let args = vec![
            "hash",
            "scan",
            "-d",
            "/path/to/dir",
            "-a",
            "sha256",
            "-b",
            "hashes.txt",
            "--hdd",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Scan {
                directory,
                algorithm,
                database,
                hdd,
                fast,
                format,
                json,
                compress,
            }) => {
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(algorithm, "sha256");
                assert_eq!(database, PathBuf::from("hashes.txt"));
                assert_eq!(hdd, true);
                assert_eq!(fast, false);
                assert_eq!(format, "quichash");
                assert_eq!(json, false);
                assert_eq!(compress, false);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_scan_command_long_flags() {
        let args = vec![
            "hash",
            "scan",
            "--directory",
            "/path/to/dir",
            "--algorithm",
            "sha256",
            "--database",
            "hashes.txt",
            "--hdd",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Scan {
                directory,
                algorithm,
                database,
                hdd,
                fast,
                format,
                json,
                compress,
            }) => {
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(algorithm, "sha256");
                assert_eq!(database, PathBuf::from("hashes.txt"));
                assert_eq!(hdd, true);
                assert_eq!(fast, false);
                assert_eq!(format, "quichash");
                assert_eq!(json, false);
                assert_eq!(compress, false);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_verify_command() {
        let args = vec!["hash", "verify", "-b", "hashes.txt", "-d", "/path/to/dir"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Verify {
                database,
                directory,
                hdd,
                json,
            }) => {
                assert_eq!(database, "hashes.txt");
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(hdd, false); // parallel by default
                assert_eq!(json, false);
            }
            _ => panic!("Expected Verify command"),
        }
    }

    #[test]
    fn test_parse_verify_command_long_flags() {
        let args = vec![
            "hash",
            "verify",
            "--database",
            "hashes.txt",
            "--directory",
            "/path/to/dir",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Verify {
                database,
                directory,
                hdd,
                json,
            }) => {
                assert_eq!(database, "hashes.txt");
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(hdd, false); // parallel by default
                assert_eq!(json, false);
            }
            _ => panic!("Expected Verify command"),
        }
    }

    #[test]
    fn test_parse_verify_command_with_hdd() {
        let args = vec![
            "hash",
            "verify",
            "-b",
            "hashes.txt",
            "-d",
            "/path/to/dir",
            "--hdd",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Verify {
                database,
                directory,
                hdd,
                json,
            }) => {
                assert_eq!(database, "hashes.txt");
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(hdd, true); // sequential mode
                assert_eq!(json, false);
            }
            _ => panic!("Expected Verify command"),
        }
    }

    #[test]
    fn test_parse_benchmark_command() {
        let args = vec!["hash", "benchmark"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Benchmark { size_mb, json }) => {
                assert_eq!(size_mb, 100); // default value
                assert_eq!(json, false);
            }
            _ => panic!("Expected Benchmark command"),
        }
    }

    #[test]
    fn test_parse_benchmark_command_with_size() {
        let args = vec!["hash", "benchmark", "-s", "50"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Benchmark { size_mb, json }) => {
                assert_eq!(size_mb, 50);
                assert_eq!(json, false);
            }
            _ => panic!("Expected Benchmark command"),
        }
    }

    #[test]
    fn test_parse_benchmark_command_long_flag() {
        let args = vec!["hash", "benchmark", "--size", "200"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Benchmark { size_mb, json }) => {
                assert_eq!(size_mb, 200);
                assert_eq!(json, false);
            }
            _ => panic!("Expected Benchmark command"),
        }
    }

    #[test]
    fn test_parse_list_command() {
        let args = vec!["hash", "list"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::List { json }) => {
                assert_eq!(json, false);
            }
            _ => panic!("Expected List command"),
        }
    }

    #[test]
    fn test_parse_invalid_subcommand() {
        // Test that an invalid subcommand is rejected
        let args = vec!["hash", "invalid-subcommand", "-d", "dir"];
        let result = Cli::try_parse_from(args);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_file_as_positional() {
        // Test that a file can be specified as positional argument
        let args = vec!["hash", "myfile.txt"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, Some("myfile.txt".to_string()));
    }

    #[test]
    fn test_parse_hash_command_no_args() {
        // Hash command without any args should work (uses defaults and stdin)
        let args = vec!["hash"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, None);
        assert_eq!(cli.algorithms, vec!["blake3"]); // default algorithm
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, false);
    }

    #[test]
    fn test_parse_scan_missing_database() {
        // Scan command requires -b flag
        let args = vec!["hash", "scan", "-d", "/path/to/dir", "-a", "sha256"];
        let result = Cli::try_parse_from(args);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_verify_missing_database() {
        // Verify command requires -b flag
        let args = vec!["hash", "verify", "-d", "/path/to/dir"];
        let result = Cli::try_parse_from(args);

        assert!(result.is_err());
    }

    #[test]
    fn test_hash_command_default_algorithm() {
        let args = vec!["hash", "test.txt"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.algorithms, vec!["blake3"]); // default algorithm
        assert_eq!(cli.fast, false); // default fast mode
    }

    #[test]
    fn test_parse_hash_command_without_file() {
        // Hash command without file should work (for stdin)
        let args = vec!["hash", "-a", "sha256"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, None);
        assert_eq!(cli.algorithms, vec!["sha256"]);
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, false);
    }

    #[test]
    fn test_parse_hash_command_stdin_with_multiple_algorithms() {
        let args = vec!["hash", "-a", "sha256", "-a", "md5"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, None);
        assert_eq!(cli.algorithms, vec!["sha256", "md5"]);
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, false);
    }

    #[test]
    fn test_scan_command_default_algorithm() {
        let args = vec!["hash", "scan", "-d", "/path/to/dir", "-b", "hashes.txt"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Scan {
                algorithm,
                fast,
                format,
                json,
                compress,
                ..
            }) => {
                assert_eq!(algorithm, "blake3"); // default algorithm
                assert_eq!(fast, false); // default fast mode
                assert_eq!(format, "quichash"); // default format
                assert_eq!(json, false); // default json
                assert_eq!(compress, false); // default compress
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_scan_command_with_fast_mode() {
        let args = vec![
            "hash",
            "scan",
            "-d",
            "/path/to/dir",
            "-a",
            "sha256",
            "-b",
            "hashes.txt",
            "-f",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Scan {
                directory,
                algorithm,
                database,
                hdd,
                fast,
                format,
                json,
                compress,
            }) => {
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(algorithm, "sha256");
                assert_eq!(database, PathBuf::from("hashes.txt"));
                assert_eq!(hdd, false);
                assert_eq!(fast, true);
                assert_eq!(format, "quichash");
                assert_eq!(json, false);
                assert_eq!(compress, false);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_scan_command_with_fast_mode_long_flag() {
        let args = vec![
            "hash",
            "scan",
            "-d",
            "/path/to/dir",
            "-a",
            "sha256",
            "-b",
            "hashes.txt",
            "--fast",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Scan {
                directory,
                algorithm,
                database,
                hdd,
                fast,
                format,
                json,
                compress,
            }) => {
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(algorithm, "sha256");
                assert_eq!(database, PathBuf::from("hashes.txt"));
                assert_eq!(hdd, false);
                assert_eq!(fast, true);
                assert_eq!(format, "quichash");
                assert_eq!(json, false);
                assert_eq!(compress, false);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_scan_command_with_hdd_and_fast() {
        let args = vec![
            "hash",
            "scan",
            "-d",
            "/path/to/dir",
            "-a",
            "sha256",
            "-b",
            "hashes.txt",
            "--hdd",
            "-f",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Scan {
                directory,
                algorithm,
                database,
                hdd,
                fast,
                format,
                json,
                compress,
            }) => {
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(algorithm, "sha256");
                assert_eq!(database, PathBuf::from("hashes.txt"));
                assert_eq!(hdd, true);
                assert_eq!(fast, true);
                assert_eq!(format, "quichash");
                assert_eq!(json, false);
                assert_eq!(compress, false);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_hash_command_with_text() {
        let args = vec!["hash", "--text", "hello world", "-a", "sha256"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, None);
        assert_eq!(cli.text, Some("hello world".to_string()));
        assert_eq!(cli.algorithms, vec!["sha256"]);
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, false);
    }

    #[test]
    fn test_parse_hash_command_with_text_short_flag() {
        let args = vec!["hash", "-t", "test string", "-a", "md5"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, None);
        assert_eq!(cli.text, Some("test string".to_string()));
        assert_eq!(cli.algorithms, vec!["md5"]);
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, false);
    }

    #[test]
    fn test_parse_hash_command_with_text_multiple_algorithms() {
        let args = vec!["hash", "-t", "hello", "-a", "sha256", "-a", "md5"];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, None);
        assert_eq!(cli.text, Some("hello".to_string()));
        assert_eq!(cli.algorithms, vec!["sha256", "md5"]);
        assert_eq!(cli.output, None);
        assert_eq!(cli.fast, false);
    }

    #[test]
    fn test_parse_hash_command_text_conflicts_with_file() {
        // Test that --text and file argument conflict
        let args = vec!["hash", "file.txt", "-t", "hello"];
        let result = Cli::try_parse_from(args);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_scan_command_with_compress() {
        let args = vec![
            "hash",
            "scan",
            "-d",
            "/path/to/dir",
            "-a",
            "sha256",
            "-b",
            "hashes.txt",
            "--compress",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Scan {
                directory,
                algorithm,
                database,
                hdd,
                fast,
                format,
                json,
                compress,
            }) => {
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(algorithm, "sha256");
                assert_eq!(database, PathBuf::from("hashes.txt"));
                assert_eq!(hdd, false);
                assert_eq!(fast, false);
                assert_eq!(format, "quichash");
                assert_eq!(json, false);
                assert_eq!(compress, true);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_scan_command_with_all_flags() {
        let args = vec![
            "hash",
            "scan",
            "-d",
            "/path/to/dir",
            "-a",
            "sha256",
            "-b",
            "hashes.txt",
            "--hdd",
            "-f",
            "--compress",
            "--json",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Scan {
                directory,
                algorithm,
                database,
                hdd,
                fast,
                format,
                json,
                compress,
            }) => {
                assert_eq!(directory, "/path/to/dir");
                assert_eq!(algorithm, "sha256");
                assert_eq!(database, PathBuf::from("hashes.txt"));
                assert_eq!(hdd, true);
                assert_eq!(fast, true);
                assert_eq!(format, "quichash");
                assert_eq!(json, true);
                assert_eq!(compress, true);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_hash_command_with_text_and_output() {
        let args = vec![
            "hash",
            "-t",
            "hello world",
            "-a",
            "sha256",
            "-b",
            "output.txt",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        assert_eq!(cli.command, None);
        assert_eq!(cli.file, None);
        assert_eq!(cli.text, Some("hello world".to_string()));
        assert_eq!(cli.algorithms, vec!["sha256"]);
        assert_eq!(cli.output, Some(PathBuf::from("output.txt")));
        assert_eq!(cli.fast, false);
    }

    #[test]
    fn test_parse_compare_command() {
        let args = vec!["hash", "compare", "db1.txt", "db2.txt"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Compare {
                database1,
                database2,
                output,
                format,
            }) => {
                assert_eq!(database1, PathBuf::from("db1.txt"));
                assert_eq!(database2, PathBuf::from("db2.txt"));
                assert_eq!(output, None);
                assert_eq!(format, "plain-text"); // default format
            }
            _ => panic!("Expected Compare command"),
        }
    }

    #[test]
    fn test_parse_compare_command_with_output() {
        let args = vec!["hash", "compare", "db1.txt", "db2.txt", "-b", "report.txt"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Compare {
                database1,
                database2,
                output,
                format,
            }) => {
                assert_eq!(database1, PathBuf::from("db1.txt"));
                assert_eq!(database2, PathBuf::from("db2.txt"));
                assert_eq!(output, Some(PathBuf::from("report.txt")));
                assert_eq!(format, "plain-text");
            }
            _ => panic!("Expected Compare command"),
        }
    }

    #[test]
    fn test_parse_compare_command_with_output_long_flag() {
        let args = vec![
            "hash",
            "compare",
            "db1.txt",
            "db2.txt",
            "--output",
            "report.txt",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Compare {
                database1,
                database2,
                output,
                format,
            }) => {
                assert_eq!(database1, PathBuf::from("db1.txt"));
                assert_eq!(database2, PathBuf::from("db2.txt"));
                assert_eq!(output, Some(PathBuf::from("report.txt")));
                assert_eq!(format, "plain-text");
            }
            _ => panic!("Expected Compare command"),
        }
    }

    #[test]
    fn test_parse_compare_command_with_json_format() {
        let args = vec!["hash", "compare", "db1.txt", "db2.txt", "--format", "json"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Compare {
                database1,
                database2,
                output,
                format,
            }) => {
                assert_eq!(database1, PathBuf::from("db1.txt"));
                assert_eq!(database2, PathBuf::from("db2.txt"));
                assert_eq!(output, None);
                assert_eq!(format, "json");
            }
            _ => panic!("Expected Compare command"),
        }
    }

    #[test]
    fn test_parse_compare_command_with_hashdeep_format() {
        let args = vec![
            "hash", "compare", "db1.txt", "db2.txt", "--format", "hashdeep",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Compare {
                database1,
                database2,
                output,
                format,
            }) => {
                assert_eq!(database1, PathBuf::from("db1.txt"));
                assert_eq!(database2, PathBuf::from("db2.txt"));
                assert_eq!(output, None);
                assert_eq!(format, "hashdeep");
            }
            _ => panic!("Expected Compare command"),
        }
    }

    #[test]
    fn test_parse_compare_command_with_all_options() {
        let args = vec![
            "hash",
            "compare",
            "db1.txt",
            "db2.txt",
            "-b",
            "report.json",
            "--format",
            "json",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Compare {
                database1,
                database2,
                output,
                format,
            }) => {
                assert_eq!(database1, PathBuf::from("db1.txt"));
                assert_eq!(database2, PathBuf::from("db2.txt"));
                assert_eq!(output, Some(PathBuf::from("report.json")));
                assert_eq!(format, "json");
            }
            _ => panic!("Expected Compare command"),
        }
    }

    #[test]
    fn test_parse_compare_command_with_compressed_databases() {
        let args = vec!["hash", "compare", "db1.txt.xz", "db2.txt.xz"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Compare {
                database1,
                database2,
                output,
                format,
            }) => {
                assert_eq!(database1, PathBuf::from("db1.txt.xz"));
                assert_eq!(database2, PathBuf::from("db2.txt.xz"));
                assert_eq!(output, None);
                assert_eq!(format, "plain-text");
            }
            _ => panic!("Expected Compare command"),
        }
    }

    #[test]
    fn test_parse_compare_command_missing_database2() {
        // Compare command requires both database arguments
        let args = vec!["hash", "compare", "db1.txt"];
        let result = Cli::try_parse_from(args);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_command() {
        let args = vec!["hash", "version"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Some(Command::Version) => {
                // Success - version command parsed correctly
            }
            _ => panic!("Expected Version command"),
        }
    }
}
