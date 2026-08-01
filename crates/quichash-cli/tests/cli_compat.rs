use std::process::Command;

fn hash_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hash"))
}

#[test]
fn version_and_default_binary_name_remain_compatible() {
    let output = hash_command().arg("version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "hash v0.0.22\n");
}

#[test]
fn cli_verifies_every_hashdeep_digest() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(temporary.path().join("file.txt"), b"hello").unwrap();
    let database = temporary.path().join("hashes.txt");
    std::fs::write(
        &database,
        "%%%% HASHDEEP-1.0\n%%%% size,md5,sha256,filename\n\
         5,5d41402abc4b2a76b9719d911017c592,2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824,file.txt\n",
    ).unwrap();

    let output = hash_command()
        .args(["verify", "-b"])
        .arg(&database)
        .arg("-d")
        .arg(temporary.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Matches:        1"), "{stdout}");
    assert!(stdout.contains("Mismatches:     0"), "{stdout}");

    std::fs::write(temporary.path().join("file.txt"), b"changed").unwrap();
    let output = hash_command()
        .args(["verify", "-b"])
        .arg(&database)
        .arg("-d")
        .arg(temporary.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Mismatches:     2"), "{stdout}");
}
