// Path normalization utilities for cross-platform path handling
// Handles both forward and backward slashes in database parsing
// Provides utilities for canonicalization and relative path handling

use std::io;
use std::path::{Component, Path, PathBuf};

/// Normalize a path string by handling both forward and backward slashes
/// Converts all path separators to the platform-specific separator
#[allow(dead_code)]
pub fn normalize_path_string(path_str: &str) -> String {
    // Replace both types of separators with the platform separator
    let normalized = if cfg!(windows) {
        // On Windows, convert forward slashes to backslashes
        path_str.replace('/', "\\")
    } else {
        // On Unix-like systems, convert backslashes to forward slashes
        path_str.replace('\\', "/")
    };

    normalized
}

/// Parse a path from a database entry, handling mixed separators
/// Returns a PathBuf with normalized separators
pub fn parse_database_path(path_str: &str) -> PathBuf {
    PathBuf::from(path_str)
}

/// Canonicalize a path if it exists, otherwise return the path as-is
/// This is useful for handling paths that may not exist yet
pub fn try_canonicalize(path: &Path) -> io::Result<PathBuf> {
    if path.exists() {
        path.canonicalize()
    } else {
        // Return absolute path without resolving symlinks
        Ok(path.to_path_buf())
    }
}

/// Get a relative path from a base directory
/// If the path cannot be made relative, returns the absolute path
#[allow(dead_code)]
pub fn get_relative_path(path: &Path, base: &Path) -> io::Result<PathBuf> {
    // Canonicalize both paths for consistent comparison
    let canonical_path = path.canonicalize()?;
    let canonical_base = base.canonicalize()?;

    // Try to strip the base prefix
    match canonical_path.strip_prefix(&canonical_base) {
        Ok(relative) => Ok(relative.to_path_buf()),
        Err(_) => {
            // If we can't make it relative, return the canonical path
            Ok(canonical_path)
        }
    }
}

/// Get a relative path from a pre-canonicalized base directory
/// This is more efficient when the base path is reused multiple times
/// If the path cannot be made relative, returns the absolute path
pub fn get_relative_path_cached(path: &Path, canonical_base: &Path) -> io::Result<PathBuf> {
    // Only canonicalize the file path
    let canonical_path = path.canonicalize()?;

    // Try to strip the base prefix
    match canonical_path.strip_prefix(canonical_base) {
        Ok(relative) => Ok(relative.to_path_buf()),
        Err(_) => {
            // If we can't make it relative, return the canonical path
            Ok(canonical_path)
        }
    }
}

/// Resolve a path that may be relative or absolute
/// If relative, resolves against the provided base directory.
/// If the raw resolved path does not exist, tries a separator-converted fallback.
pub fn resolve_path(path: &Path, base_dir: &Path) -> PathBuf {
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };

    if resolved.exists() {
        return resolved;
    }

    if let Some(path_str) = path.to_str() {
        #[cfg(not(windows))]
        if path_str.contains('\\') {
            let fallback_str = path_str.replace('\\', "/");
            let fallback = if Path::new(&fallback_str).is_absolute() {
                PathBuf::from(&fallback_str)
            } else {
                base_dir.join(&fallback_str)
            };
            if fallback.exists() {
                return fallback;
            }
        }

        #[cfg(windows)]
        if path_str.contains('/') {
            let fallback_str = path_str.replace('/', "\\");
            let fallback = if Path::new(&fallback_str).is_absolute() {
                PathBuf::from(&fallback_str)
            } else {
                base_dir.join(&fallback_str)
            };
            if fallback.exists() {
                return fallback;
            }
        }
    }

    resolved
}

/// Clean a path by removing redundant components like "." and ".."
/// This provides a normalized form without requiring the path to exist
#[allow(dead_code)]
pub fn clean_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            Component::CurDir => {
                // Skip "." components
                continue;
            }
            Component::ParentDir => {
                // Handle ".." by popping the last component if possible
                if !components.is_empty() {
                    let last = components.last();
                    // Only pop if the last component is not ".." or a root
                    if let Some(Component::Normal(_)) = last {
                        components.pop();
                        continue;
                    }
                }
                components.push(component);
            }
            _ => {
                components.push(component);
            }
        }
    }

    // Reconstruct the path from components
    let mut result = PathBuf::new();
    for component in components {
        result.push(component);
    }

    // If the result is empty, return current directory
    if result.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        let result = get_relative_path_cached(&file, &canonical_base);
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
}
