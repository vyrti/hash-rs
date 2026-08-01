use std::fs;
use std::process::Command;

use serde_json::Value;
use tempfile::tempdir;

fn hash_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hash")
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn parse_stdout_json(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not pure JSON: {}\nstdout:\n{}\nstderr:\n{}",
            e,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn test_scan_json_stdout_is_pure_json() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("hashes.txt");
    fs::write(temp_dir.path().join("file.txt"), b"hello").unwrap();

    let output = Command::new(hash_bin())
        .args([
            "scan",
            "-d",
            temp_dir.path().to_str().unwrap(),
            "-b",
            db_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert_success(&output);
    let json = parse_stdout_json(&output);
    assert_eq!(json["stats"]["files_processed"], 1);
}

#[test]
fn test_dedup_json_stdout_is_pure_json() {
    let temp_dir = tempdir().unwrap();
    fs::write(temp_dir.path().join("a.txt"), b"x").unwrap();
    fs::write(temp_dir.path().join("b.txt"), b"x").unwrap();

    let output = Command::new(hash_bin())
        .args(["dedup", "-d", temp_dir.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert_success(&output);
    let json = parse_stdout_json(&output);
    assert_eq!(json["stats"]["duplicate_groups"], 1);
}

#[test]
fn test_verify_json_stdout_is_pure_json_for_multiple_pairs() {
    let temp_dir = tempdir().unwrap();
    let dir1 = temp_dir.path().join("dir1");
    let dir2 = temp_dir.path().join("dir2");
    let db_path = temp_dir.path().join("hashes.txt");
    fs::create_dir_all(&dir1).unwrap();
    fs::create_dir_all(&dir2).unwrap();
    fs::write(dir1.join("a.txt"), b"x").unwrap();
    fs::write(dir2.join("a.txt"), b"x").unwrap();

    let scan_output = Command::new(hash_bin())
        .args([
            "scan",
            "-d",
            dir1.to_str().unwrap(),
            "-b",
            db_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success(&scan_output);

    let dir_pattern = temp_dir.path().join("dir*").to_string_lossy().into_owned();
    let output = Command::new(hash_bin())
        .args([
            "verify",
            "-b",
            db_path.to_str().unwrap(),
            "-d",
            &dir_pattern,
            "--json",
        ])
        .output()
        .unwrap();

    assert_success(&output);
    let json = parse_stdout_json(&output);
    assert_eq!(json["report"]["matches"], 2);
}

#[test]
fn test_parallel_hashdeep_scan_writes_correct_size() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("hashes.txt");
    fs::write(temp_dir.path().join("file.txt"), b"hello").unwrap();

    let output = Command::new(hash_bin())
        .args([
            "scan",
            "-d",
            temp_dir.path().to_str().unwrap(),
            "-b",
            db_path.to_str().unwrap(),
            "--format",
            "hashdeep",
        ])
        .output()
        .unwrap();

    assert_success(&output);
    let database = fs::read_to_string(&db_path).unwrap();
    let data_line = database
        .lines()
        .find(|line| !line.is_empty() && !line.starts_with('%') && !line.starts_with('#'))
        .unwrap();
    assert!(
        data_line.starts_with("5,"),
        "unexpected hashdeep data line: {}",
        data_line
    );
}

#[cfg(unix)]
#[test]
fn test_standard_scan_verify_round_trip_preserves_backslash_filename() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("hashes.txt");
    fs::write(temp_dir.path().join(r"a\b.txt"), b"x").unwrap();

    let scan_output = Command::new(hash_bin())
        .args([
            "scan",
            "-d",
            temp_dir.path().to_str().unwrap(),
            "-b",
            db_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success(&scan_output);

    let verify_output = Command::new(hash_bin())
        .args([
            "verify",
            "-b",
            db_path.to_str().unwrap(),
            "-d",
            temp_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert_success(&verify_output);
    let json = parse_stdout_json(&verify_output);
    assert_eq!(json["report"]["matches"], 1);
    assert_eq!(json["report"]["missing_files"].as_array().unwrap().len(), 0);
    assert_eq!(json["report"]["new_files"].as_array().unwrap().len(), 0);
}

#[cfg(unix)]
#[test]
fn test_standard_scan_verify_round_trip_preserves_spacey_filenames() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("hashes.txt");
    fs::write(temp_dir.path().join(" leading.txt"), b"x").unwrap();
    fs::write(temp_dir.path().join("trailing.txt "), b"y").unwrap();

    let scan_output = Command::new(hash_bin())
        .args([
            "scan",
            "-d",
            temp_dir.path().to_str().unwrap(),
            "-b",
            db_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success(&scan_output);

    let verify_output = Command::new(hash_bin())
        .args([
            "verify",
            "-b",
            db_path.to_str().unwrap(),
            "-d",
            temp_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert_success(&verify_output);
    let json = parse_stdout_json(&verify_output);
    assert_eq!(json["report"]["matches"], 2);
    assert_eq!(json["report"]["missing_files"].as_array().unwrap().len(), 0);
    assert_eq!(json["report"]["new_files"].as_array().unwrap().len(), 0);
}

#[cfg(unix)]
#[test]
fn test_hashdeep_scan_verify_round_trip_preserves_spacey_filenames() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("hashes.txt");
    fs::write(temp_dir.path().join(" leading.txt"), b"x").unwrap();
    fs::write(temp_dir.path().join("trailing.txt "), b"y").unwrap();

    let scan_output = Command::new(hash_bin())
        .args([
            "scan",
            "-d",
            temp_dir.path().to_str().unwrap(),
            "-b",
            db_path.to_str().unwrap(),
            "--format",
            "hashdeep",
            "--hdd",
        ])
        .output()
        .unwrap();
    assert_success(&scan_output);

    let verify_output = Command::new(hash_bin())
        .args([
            "verify",
            "-b",
            db_path.to_str().unwrap(),
            "-d",
            temp_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert_success(&verify_output);
    let json = parse_stdout_json(&verify_output);
    assert_eq!(json["report"]["matches"], 2);
    assert_eq!(json["report"]["missing_files"].as_array().unwrap().len(), 0);
    assert_eq!(json["report"]["new_files"].as_array().unwrap().len(), 0);
}

#[test]
fn test_hash_command_can_target_literal_bracket_filename() {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("file[1].txt");
    fs::write(&file_path, b"hello").unwrap();

    let output = Command::new(hash_bin())
        .arg(file_path.to_str().unwrap())
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("file[1].txt"), "stdout:\n{}", stdout);
}

#[test]
fn test_hash_json_file_count_counts_unique_files() {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("file.txt");
    fs::write(&file_path, b"hello").unwrap();

    let output = Command::new(hash_bin())
        .args([
            file_path.to_str().unwrap(),
            "-a",
            "sha256",
            "-a",
            "md5",
            "--json",
        ])
        .output()
        .unwrap();

    assert_success(&output);
    let json = parse_stdout_json(&output);
    assert_eq!(json["metadata"]["file_count"], 1);
}
