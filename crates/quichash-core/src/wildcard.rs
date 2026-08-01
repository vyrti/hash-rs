//! Wildcard expansion utilities.
// Handles cross-platform wildcard pattern matching using glob

use crate::error::HashUtilityError;
use std::path::{Path, PathBuf};

/// Expand a wildcard pattern into a list of matching file paths
///
/// Supports patterns like:
/// - `*.txt` - matches all .txt files in current directory
/// - `file?.bin` - matches file1.bin, fileA.bin, etc.
/// - `[abc]*.jpg` - matches files starting with a, b, or c
/// - `data/*/hashes` - matches hashes file in any subdirectory of data
///
/// # Arguments
/// * `pattern` - The wildcard pattern to expand
///
/// # Returns
/// A vector of matching file paths, sorted alphabetically
///
/// # Errors
/// Returns an error if the pattern is invalid or no matches are found
pub fn expand_pattern(pattern: &str) -> Result<Vec<PathBuf>, HashUtilityError> {
    // Check if the pattern contains wildcard characters
    if !contains_wildcard(pattern) {
        // Not a wildcard pattern, return as-is
        return Ok(vec![PathBuf::from(pattern)]);
    }

    // A real filename may legally contain glob metacharacters.
    if Path::new(pattern).exists() {
        return Ok(vec![PathBuf::from(pattern)]);
    }

    // Use glob to expand the pattern
    let mut matches = Vec::new();

    match glob::glob(pattern) {
        Ok(paths) => {
            for entry in paths {
                match entry {
                    Ok(path) => matches.push(path),
                    Err(e) => {
                        return Err(HashUtilityError::InvalidArguments {
                            message: format!("Error reading glob pattern '{}': {}", pattern, e),
                        });
                    }
                }
            }
        }
        Err(e) => {
            return Err(HashUtilityError::InvalidArguments {
                message: format!("Invalid glob pattern '{}': {}", pattern, e),
            });
        }
    }

    // Check if any matches were found
    if matches.is_empty() {
        return Err(HashUtilityError::InvalidArguments {
            message: format!("No files match pattern '{}'", pattern),
        });
    }

    // Sort matches for consistent ordering
    matches.sort();

    Ok(matches)
}

/// Check if a string contains wildcard characters
fn contains_wildcard(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_contains_wildcard() {
        assert!(contains_wildcard("*.txt"));
        assert!(contains_wildcard("file?.bin"));
        assert!(contains_wildcard("[abc]*.jpg"));
        assert!(contains_wildcard("data/*/hashes"));
        assert!(!contains_wildcard("file.txt"));
        assert!(!contains_wildcard("path/to/file.bin"));
    }

    #[test]
    fn test_expand_pattern_no_wildcard() {
        let result = expand_pattern("file.txt").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], PathBuf::from("file.txt"));
    }

    #[test]
    fn test_expand_pattern_no_matches() {
        let result = expand_pattern("nonexistent*.txt");
        assert!(result.is_err());

        if let Err(HashUtilityError::InvalidArguments { message }) = result {
            assert!(message.contains("No files match pattern"));
        } else {
            panic!("Expected InvalidArguments error");
        }
    }

    #[test]
    fn test_expand_pattern_with_matches() {
        // Create temporary test files
        let temp_dir = std::env::temp_dir();
        let test_files = vec![
            temp_dir.join("test_wildcard_1.txt"),
            temp_dir.join("test_wildcard_2.txt"),
            temp_dir.join("test_wildcard_3.txt"),
        ];

        // Create the test files
        for file in &test_files {
            let mut f = fs::File::create(file).unwrap();
            f.write_all(b"test").unwrap();
        }

        // Test wildcard expansion
        let pattern = temp_dir
            .join("test_wildcard_*.txt")
            .to_string_lossy()
            .to_string();
        let result = expand_pattern(&pattern).unwrap();

        assert_eq!(result.len(), 3);
        assert!(result
            .iter()
            .all(|p| p.to_string_lossy().contains("test_wildcard_")));

        // Clean up test files
        for file in &test_files {
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn test_expand_pattern_question_mark() {
        // Create temporary test files
        let temp_dir = std::env::temp_dir();
        let test_files = vec![
            temp_dir.join("test_q1.bin"),
            temp_dir.join("test_q2.bin"),
            temp_dir.join("test_qa.bin"),
        ];

        // Create the test files
        for file in &test_files {
            let mut f = fs::File::create(file).unwrap();
            f.write_all(b"test").unwrap();
        }

        // Test wildcard expansion with ?
        let pattern = temp_dir.join("test_q?.bin").to_string_lossy().to_string();
        let result = expand_pattern(&pattern).unwrap();

        assert_eq!(result.len(), 3);

        // Clean up test files
        for file in &test_files {
            let _ = fs::remove_file(file);
        }
    }

    #[test]
    fn test_expand_pattern_prefers_literal_existing_path() {
        let temporary = tempdir().unwrap();
        let file = temporary.path().join("file[1].txt");
        fs::write(&file, b"test").unwrap();

        assert_eq!(expand_pattern(file.to_str().unwrap()).unwrap(), vec![file]);
    }
}
