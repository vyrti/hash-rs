use super::*;

#[test]
fn test_parse_hash_command() {
    let args = vec!["hash", "test.txt", "-a", "sha256"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.command, None);
    assert_eq!(cli.file, Some("test.txt".to_string()));
    assert_eq!(cli.algorithms, vec!["sha256"]);
    assert_eq!(cli.output, None);
    assert!(!cli.fast);
    assert!(!cli.json);
}

#[test]
fn test_parse_hash_command_multiple_algorithms() {
    let args = vec!["hash", "test.txt", "-a", "sha256", "-a", "md5"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.command, None);
    assert_eq!(cli.file, Some("test.txt".to_string()));
    assert_eq!(cli.algorithms, vec!["sha256", "md5"]);
    assert_eq!(cli.output, None);
    assert!(!cli.fast);
}

#[test]
fn test_parse_hash_command_with_output() {
    let args = vec!["hash", "test.txt", "-a", "sha256", "-b", "output.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.command, None);
    assert_eq!(cli.file, Some("test.txt".to_string()));
    assert_eq!(cli.algorithms, vec!["sha256"]);
    assert_eq!(cli.output, Some(PathBuf::from("output.txt")));
    assert!(!cli.fast);
}

#[test]
fn test_parse_hash_command_long_flags() {
    let args = vec!["hash", "test.txt", "--algorithm", "sha256"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.command, None);
    assert_eq!(cli.file, Some("test.txt".to_string()));
    assert_eq!(cli.algorithms, vec!["sha256"]);
    assert!(!cli.fast);
}

#[test]
fn test_parse_hash_command_with_fast_mode() {
    let args = vec!["hash", "test.txt", "-a", "sha256", "-f"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.command, None);
    assert_eq!(cli.file, Some("test.txt".to_string()));
    assert_eq!(cli.algorithms, vec!["sha256"]);
    assert_eq!(cli.output, None);
    assert!(cli.fast);
}

#[test]
fn test_parse_hash_command_with_fast_mode_long_flag() {
    let args = vec!["hash", "test.txt", "--fast"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.command, None);
    assert_eq!(cli.file, Some("test.txt".to_string()));
    assert_eq!(cli.algorithms, vec!["blake3"]); // default
    assert_eq!(cli.output, None);
    assert!(cli.fast);
}

#[test]
fn test_parse_hash_command_with_fast_and_multiple_algorithms() {
    let args = vec!["hash", "test.txt", "-a", "sha256", "-a", "md5", "-f"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.command, None);
    assert_eq!(cli.file, Some("test.txt".to_string()));
    assert_eq!(cli.algorithms, vec!["sha256", "md5"]);
    assert_eq!(cli.output, None);
    assert!(cli.fast);
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
    assert!(!cli.fast);
}

#[test]
fn test_hash_command_default_algorithm() {
    let args = vec!["hash", "test.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.command, None);
    assert_eq!(cli.algorithms, vec!["blake3"]); // default algorithm
    assert!(!cli.fast); // default fast mode
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
    assert!(!cli.fast);
}

#[test]
fn test_parse_hash_command_stdin_with_multiple_algorithms() {
    let args = vec!["hash", "-a", "sha256", "-a", "md5"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.command, None);
    assert_eq!(cli.file, None);
    assert_eq!(cli.algorithms, vec!["sha256", "md5"]);
    assert_eq!(cli.output, None);
    assert!(!cli.fast);
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
    assert!(!cli.fast);
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
    assert!(!cli.fast);
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
    assert!(!cli.fast);
}

#[test]
fn test_parse_hash_command_text_conflicts_with_file() {
    // Test that --text and file argument conflict
    let args = vec!["hash", "file.txt", "-t", "hello"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
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
    assert!(!cli.fast);
}
