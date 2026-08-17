use super::*;

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
            assert!(!hdd); // parallel by default
            assert!(!json);
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
            assert!(!hdd); // parallel by default
            assert!(!json);
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
            assert!(hdd); // sequential mode
            assert!(!json);
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
            assert!(!json);
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
            assert!(!json);
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
            assert!(!json);
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
            assert!(!json);
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
fn test_parse_verify_missing_database() {
    // Verify command requires -b flag
    let args = vec!["hash", "verify", "-d", "/path/to/dir"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
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
