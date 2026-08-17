use super::*;

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
            assert!(!hdd);
            assert!(!fast);
            assert_eq!(format, "quichash");
            assert!(!json);
            assert!(!compress);
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
            assert!(hdd);
            assert!(!fast);
            assert_eq!(format, "quichash");
            assert!(!json);
            assert!(!compress);
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
            assert!(hdd);
            assert!(!fast);
            assert_eq!(format, "quichash");
            assert!(!json);
            assert!(!compress);
        }
        _ => panic!("Expected Scan command"),
    }
}

#[test]
fn test_parse_scan_missing_database() {
    // Scan command requires -b flag
    let args = vec!["hash", "scan", "-d", "/path/to/dir", "-a", "sha256"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
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
            assert!(!fast); // default fast mode
            assert_eq!(format, "quichash"); // default format
            assert!(!json); // default json
            assert!(!compress); // default compress
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
            assert!(!hdd);
            assert!(fast);
            assert_eq!(format, "quichash");
            assert!(!json);
            assert!(!compress);
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
            assert!(!hdd);
            assert!(fast);
            assert_eq!(format, "quichash");
            assert!(!json);
            assert!(!compress);
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
            assert!(hdd);
            assert!(fast);
            assert_eq!(format, "quichash");
            assert!(!json);
            assert!(!compress);
        }
        _ => panic!("Expected Scan command"),
    }
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
            assert!(!hdd);
            assert!(!fast);
            assert_eq!(format, "quichash");
            assert!(!json);
            assert!(compress);
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
            assert!(hdd);
            assert!(fast);
            assert_eq!(format, "quichash");
            assert!(json);
            assert!(compress);
        }
        _ => panic!("Expected Scan command"),
    }
}
