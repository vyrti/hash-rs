//! `.hashignore` handling.
// Supports gitignore-style patterns for excluding files from scans

use crate::error::HashUtilityError;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::Path;

/// Handler for .hashignore files
///
/// Reads .hashignore files from the scanned directory and parent directories,
/// supporting gitignore-style patterns including globs, negation, and comments.
pub struct IgnoreHandler {
    gitignore: Gitignore,
}

impl IgnoreHandler {
    /// Create a new IgnoreHandler by searching for .hashignore files
    ///
    /// Searches for .hashignore in the specified directory and all parent directories,
    /// building a combined ignore pattern matcher.
    ///
    /// # Arguments
    /// * `root` - Root directory to start searching from
    ///
    /// # Returns
    /// A new IgnoreHandler with loaded patterns
    pub fn new(root: &Path) -> Result<Self, HashUtilityError> {
        let mut builder = GitignoreBuilder::new(root);

        // Always exclude .hashignore files themselves
        builder
            .add_line(None, ".hashignore")
            .map_err(|e| HashUtilityError::InvalidArguments {
                message: format!("Failed to add .hashignore pattern: {}", e),
            })?;

        // Search for .hashignore files in the directory and parent directories
        let mut current_dir = Some(root);
        let mut found_any = false;

        while let Some(dir) = current_dir {
            let hashignore_path = dir.join(".hashignore");

            if hashignore_path.exists() && hashignore_path.is_file() {
                // Add this .hashignore file to the builder
                if let Some(e) = builder.add(&hashignore_path) {
                    eprintln!(
                        "Warning: Failed to parse .hashignore at {}: {}",
                        hashignore_path.display(),
                        e
                    );
                } else {
                    found_any = true;
                }
            }

            // Move to parent directory
            current_dir = dir.parent();
        }

        // Build the gitignore matcher
        let gitignore = builder
            .build()
            .map_err(|e| HashUtilityError::InvalidArguments {
                message: format!("Failed to build ignore patterns: {}", e),
            })?;

        if found_any {
            eprintln!("Loaded .hashignore patterns");
        }

        Ok(Self { gitignore })
    }

    /// Check if a file should be ignored
    ///
    /// # Arguments
    /// * `path` - Path to check (relative to the root directory)
    /// * `is_dir` - Whether the path is a directory
    ///
    /// # Returns
    /// true if the file should be ignored, false otherwise
    pub fn should_ignore(&self, path: &Path, is_dir: bool) -> bool {
        self.gitignore.matched(path, is_dir).is_ignore()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_ignore_handler_no_hashignore() {
        // Create a temporary directory without .hashignore
        let test_dir = "test_ignore_no_file";
        fs::create_dir_all(test_dir).unwrap();

        // Create handler
        let handler = IgnoreHandler::new(Path::new(test_dir)).unwrap();

        // No files should be ignored
        assert!(!handler.should_ignore(Path::new("test.txt"), false));
        assert!(!handler.should_ignore(Path::new("subdir/file.txt"), false));

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_ignore_handler_basic_patterns() {
        // Create a temporary directory with .hashignore
        let test_dir = "test_ignore_basic";
        fs::create_dir_all(test_dir).unwrap();

        // Create .hashignore with basic patterns
        let hashignore_content = "*.log\n*.tmp\ntemp/\n";
        fs::write(format!("{}/.hashignore", test_dir), hashignore_content).unwrap();

        // Create handler
        let handler = IgnoreHandler::new(Path::new(test_dir)).unwrap();

        // Test patterns
        assert!(handler.should_ignore(Path::new("test.log"), false));
        assert!(handler.should_ignore(Path::new("file.tmp"), false));
        assert!(handler.should_ignore(Path::new("temp"), true));
        assert!(!handler.should_ignore(Path::new("test.txt"), false));
        assert!(!handler.should_ignore(Path::new("data.csv"), false));

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_ignore_handler_negation() {
        // Create a temporary directory with .hashignore
        let test_dir = "test_ignore_negation";
        fs::create_dir_all(test_dir).unwrap();

        // Create .hashignore with negation pattern
        let hashignore_content = "*.log\n!important.log\n";
        fs::write(format!("{}/.hashignore", test_dir), hashignore_content).unwrap();

        // Create handler
        let handler = IgnoreHandler::new(Path::new(test_dir)).unwrap();

        // Test patterns
        assert!(handler.should_ignore(Path::new("test.log"), false));
        assert!(handler.should_ignore(Path::new("debug.log"), false));
        assert!(!handler.should_ignore(Path::new("important.log"), false));

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_ignore_handler_comments() {
        // Create a temporary directory with .hashignore
        let test_dir = "test_ignore_comments";
        fs::create_dir_all(test_dir).unwrap();

        // Create .hashignore with comments
        let hashignore_content = "# This is a comment\n*.log\n# Another comment\n*.tmp\n";
        fs::write(format!("{}/.hashignore", test_dir), hashignore_content).unwrap();

        // Create handler
        let handler = IgnoreHandler::new(Path::new(test_dir)).unwrap();

        // Test patterns (comments should be ignored)
        assert!(handler.should_ignore(Path::new("test.log"), false));
        assert!(handler.should_ignore(Path::new("file.tmp"), false));
        assert!(!handler.should_ignore(Path::new("test.txt"), false));

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_ignore_handler_subdirectories() {
        // Create a temporary directory with .hashignore
        let test_dir = "test_ignore_subdir";
        fs::create_dir_all(test_dir).unwrap();

        // Create .hashignore with directory patterns
        let hashignore_content = "build/\nnode_modules/\n*.o\n";
        fs::write(format!("{}/.hashignore", test_dir), hashignore_content).unwrap();

        // Create handler
        let handler = IgnoreHandler::new(Path::new(test_dir)).unwrap();

        // Test directory patterns
        assert!(handler.should_ignore(Path::new("build"), true));
        assert!(handler.should_ignore(Path::new("node_modules"), true));
        assert!(handler.should_ignore(Path::new("src/main.o"), false));
        assert!(!handler.should_ignore(Path::new("src"), true));
        assert!(!handler.should_ignore(Path::new("src/main.c"), false));

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }
}
