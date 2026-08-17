use quichash_core::path_utils::{
    clean_path, get_relative_path, get_relative_path_cached, normalize_path_string,
    parse_database_path, resolve_path, try_canonicalize,
};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn test_normalize_path_string_forward_slash() {
    let input = "path/to/file.txt";
    let result = normalize_path_string(input);

    if cfg!(windows) {
        assert_eq!(result, "path\\to\\file.txt");
    } else {
        assert_eq!(result, "path/to/file.txt");
    }
}

#[test]
fn test_normalize_path_string_backward_slash() {
    let input = "path\\to\\file.txt";
    let result = normalize_path_string(input);

    if cfg!(windows) {
        assert_eq!(result, "path\\to\\file.txt");
    } else {
        assert_eq!(result, "path/to/file.txt");
    }
}

#[test]
fn test_normalize_path_string_mixed() {
    let input = "path/to\\mixed/file.txt";
    let result = normalize_path_string(input);

    if cfg!(windows) {
        assert_eq!(result, "path\\to\\mixed\\file.txt");
    } else {
        assert_eq!(result, "path/to/mixed/file.txt");
    }
}

#[test]
fn test_parse_database_path() {
    let input = "path/to\\file.txt";
    let result = parse_database_path(input);

    // Should create a valid PathBuf
    assert!(result.to_str().is_some());
}

#[test]
fn test_try_canonicalize_existing_file() {
    // Create a temporary file
    let test_file = "test_canonicalize_temp.txt";
    fs::write(test_file, b"test").unwrap();

    let result = try_canonicalize(Path::new(test_file));
    assert!(result.is_ok());

    let canonical = result.unwrap();
    assert!(canonical.is_absolute());

    // Cleanup
    fs::remove_file(test_file).unwrap();
}

#[test]
fn test_try_canonicalize_nonexistent_file() {
    let result = try_canonicalize(Path::new("nonexistent_file_xyz.txt"));
    assert!(result.is_ok());

    // Should return the path as-is
    let path = result.unwrap();
    assert_eq!(path, PathBuf::from("nonexistent_file_xyz.txt"));
}

#[test]
fn test_get_relative_path() {
    // Create a temporary directory structure
    let test_dir = "test_relative_path";
    fs::create_dir_all(format!("{}/subdir", test_dir)).unwrap();

    let file_path = format!("{}/subdir/file.txt", test_dir);
    fs::write(&file_path, b"test").unwrap();

    // Get relative path
    let base = Path::new(test_dir).canonicalize().unwrap();
    let file = Path::new(&file_path).canonicalize().unwrap();

    let result = get_relative_path(&file, &base);
    assert!(result.is_ok());

    let relative = result.unwrap();
    assert!(!relative.is_absolute());

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_get_relative_path_cached() {
    // Create a temporary directory structure
    let test_dir = "test_relative_path_cached";
    fs::create_dir_all(format!("{}/subdir", test_dir)).unwrap();

    let file_path = format!("{}/subdir/file.txt", test_dir);
    fs::write(&file_path, b"test").unwrap();

    // Pre-canonicalize base path (simulating cached scenario)
    let canonical_base = Path::new(test_dir).canonicalize().unwrap();
    let file = Path::new(&file_path);

    // Get relative path using cached base
    let result = get_relative_path_cached(file, &canonical_base);
    assert!(result.is_ok());

    let relative = result.unwrap();
    assert!(!relative.is_absolute());

    // Verify it produces the same result as the non-cached version
    let file_canonical = file.canonicalize().unwrap();
    let result_original = get_relative_path(&file_canonical, Path::new(test_dir));
    assert!(result_original.is_ok());
    assert_eq!(relative, result_original.unwrap());

    // Cleanup
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_resolve_path_relative() {
    let base = Path::new("/base/dir");
    let relative = Path::new("subdir/file.txt");

    let result = resolve_path(relative, base);
    assert_eq!(result, PathBuf::from("/base/dir/subdir/file.txt"));
}

#[test]
fn test_resolve_path_absolute() {
    let base = Path::new("/base/dir");
    let absolute = Path::new("/absolute/path/file.txt");

    let result = resolve_path(absolute, base);
    assert_eq!(result, PathBuf::from("/absolute/path/file.txt"));
}

#[cfg(not(windows))]
#[test]
fn test_resolve_path_falls_back_to_separator_conversion() {
    let test_dir = "test_resolve_path_fallback";
    fs::create_dir_all(format!("{}/subdir", test_dir)).unwrap();

    let file_path = format!("{}/subdir/file.txt", test_dir);
    fs::write(&file_path, b"test").unwrap();

    let base = Path::new(test_dir).canonicalize().unwrap();
    let result = resolve_path(Path::new("subdir\\file.txt"), &base);

    assert_eq!(result, base.join("subdir/file.txt"));

    fs::remove_dir_all(test_dir).unwrap();
}

#[cfg(not(windows))]
#[test]
fn test_resolve_path_prefers_literal_backslash_filename() {
    let test_dir = "test_resolve_path_literal_backslash";
    fs::create_dir_all(test_dir).unwrap();

    let file_path = format!("{}/a\\b.txt", test_dir);
    fs::write(&file_path, b"test").unwrap();

    let base = Path::new(test_dir).canonicalize().unwrap();
    let result = resolve_path(Path::new("a\\b.txt"), &base);

    assert_eq!(result, base.join("a\\b.txt"));

    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn test_clean_path_with_current_dir() {
    let path = Path::new("./path/./to/./file.txt");
    let result = clean_path(path);

    assert_eq!(result, PathBuf::from("path/to/file.txt"));
}

#[test]
fn test_clean_path_with_parent_dir() {
    let path = Path::new("path/to/../file.txt");
    let result = clean_path(path);

    assert_eq!(result, PathBuf::from("path/file.txt"));
}

#[test]
fn test_clean_path_complex() {
    let path = Path::new("./path/./to/../../other/file.txt");
    let result = clean_path(path);

    assert_eq!(result, PathBuf::from("other/file.txt"));
}

#[test]
fn test_clean_path_empty() {
    let path = Path::new("./.");
    let result = clean_path(path);

    assert_eq!(result, PathBuf::from("."));
}

#[test]
fn test_clean_path_parent_only() {
    let path = Path::new("..");
    let result = clean_path(path);

    assert_eq!(result, PathBuf::from(".."));
}
