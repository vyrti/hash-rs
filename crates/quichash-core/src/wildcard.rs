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
pub fn contains_wildcard(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}
