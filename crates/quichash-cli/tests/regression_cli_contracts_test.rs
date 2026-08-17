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
fn scan_normalizes_requested_database_extensions() {
    for (requested, expected) in [
        ("hashes", "hashes.qh"),
        ("legacy.txt", "legacy.qh"),
        ("legacy.db", "legacy.qh"),
        ("old.txt.xz", "old.qh"),
    ] {
        let temporary = tempdir().unwrap();
        fs::write(temporary.path().join("file.bin"), b"data").unwrap();
        let output = Command::new(hash_bin())
            .args(["scan", "-d"])
            .arg(temporary.path())
            .args(["-b", requested])
            .current_dir(temporary.path())
            .output()
            .unwrap();
        assert_success(&output);
        assert!(temporary.path().join(expected).is_file(), "{requested}");
        assert!(!temporary.path().join(requested).is_file() || requested == expected);
    }
}

#[test]
fn scan_supports_explicit_quichash_and_canonical_hashdeep_paths() {
    let temporary = tempdir().unwrap();
    fs::write(temporary.path().join("file.bin"), b"data").unwrap();

    let quichash = Command::new(hash_bin())
        .args(["scan", "-d"])
        .arg(temporary.path())
        .args(["-b", "native.txt", "--format", "quichash"])
        .current_dir(temporary.path())
        .output()
        .unwrap();
    assert_success(&quichash);
    assert!(temporary.path().join("native.qh").is_file());

    let hashdeep = Command::new(hash_bin())
        .args(["scan", "-d"])
        .arg(temporary.path())
        .args(["-b", "deep.txt", "--format", "hashdeep"])
        .current_dir(temporary.path())
        .output()
        .unwrap();
    assert_success(&hashdeep);
    assert!(temporary.path().join("deep.hashdeep").is_file());
}

#[test]
fn compressed_scan_creates_only_canonical_qh_xz_output() {
    let temporary = tempdir().unwrap();
    fs::write(temporary.path().join("file.bin"), b"data").unwrap();
    let output = Command::new(hash_bin())
        .args(["scan", "-d"])
        .arg(temporary.path())
        .args(["-b", "hashes.txt", "--compress", "--json"])
        .current_dir(temporary.path())
        .output()
        .unwrap();
    assert_success(&output);
    let json = parse_stdout_json(&output);
    assert_eq!(json["metadata"]["output_file"], "hashes.qh.xz");
    assert!(temporary.path().join("hashes.qh.xz").is_file());
    assert!(!temporary.path().join("hashes.qh").exists());
    assert!(!temporary.path().join("hashes.txt").exists());
}

#[test]
fn test_scan_json_stdout_is_pure_json() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("hashes.qh");
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
    let db_path = temp_dir.path().join("hashes.qh");
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

#[cfg(unix)]
#[test]
fn test_quichash_scan_verify_round_trip_preserves_backslash_filename() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("hashes.qh");
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
fn test_quichash_scan_verify_round_trip_preserves_spacey_filenames() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("hashes.qh");
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
