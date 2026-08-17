//! Recursive directory scanning.
// Handles recursive directory traversal and hash computation

use crossbeam_channel::Sender;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::database::DatabaseFormat;
use crate::error::HashUtilityError;
use crate::hash::HashComputer;

mod parallel;
mod sequential;
#[cfg(test)]
mod tests;

/// Backward-compatible error name for directory scan operations.
pub type ScanError = HashUtilityError;

/// Statistics collected during a directory scan
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanStats {
    /// Number of files hashed successfully.
    pub files_processed: usize,
    /// Number of files that could not be processed.
    pub files_failed: usize,
    /// Sum of sizes of successfully processed files.
    pub total_bytes: u64,
    #[serde(serialize_with = "serialize_duration")]
    /// Elapsed scan time, serialized as seconds.
    pub duration: Duration,
}

// Helper function to serialize Duration as seconds
fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_f64(duration.as_secs_f64())
}

/// Engine for scanning directories and generating hash databases
pub struct ScanEngine {
    computer: HashComputer,
    parallel: bool,
    fast_mode: bool,
    use_ignore: bool,
    format: DatabaseFormat,
    excluded_output: Option<PathBuf>,
}

impl ScanEngine {
    /// Create a new ScanEngine with default settings
    pub fn new() -> Self {
        Self {
            computer: HashComputer::new(),
            parallel: false,
            fast_mode: false,
            use_ignore: true,
            format: DatabaseFormat::Quichash,
            excluded_output: None,
        }
    }

    /// Create a new ScanEngine with parallel processing enabled
    pub fn with_parallel(parallel: bool) -> Self {
        Self {
            computer: HashComputer::new(),
            parallel,
            fast_mode: false,
            use_ignore: true,
            format: DatabaseFormat::Quichash,
            excluded_output: None,
        }
    }

    /// Enable or disable fast mode for large file hashing
    pub fn with_fast_mode(mut self, fast_mode: bool) -> Self {
        self.fast_mode = fast_mode;
        self
    }

    /// Enable or disable .hashignore file support
    pub fn with_ignore(mut self, use_ignore: bool) -> Self {
        self.use_ignore = use_ignore;
        self
    }

    /// Set the output format
    pub fn with_format(mut self, format: DatabaseFormat) -> Self {
        self.format = format;
        self
    }

    /// Exclude an additional output path from traversal.
    ///
    /// This is useful when a scan writes a temporary plain database before
    /// replacing an existing compressed database at a different path.
    pub fn with_excluded_output(mut self, path: impl Into<PathBuf>) -> Self {
        self.excluded_output = Some(path.into());
        self
    }

    /// Scan a directory recursively and write hash database to output file
    ///
    /// # Arguments
    /// * `root` - Root directory to scan
    /// * `algorithm` - Hash algorithm to use
    /// * `output` - Output file path for hash database
    ///
    /// # Returns
    /// Statistics about the scan operation
    pub fn scan_directory(
        &self,
        root: &Path,
        algorithm: &str,
        output: &Path,
    ) -> Result<ScanStats, ScanError> {
        let start_time = Instant::now();

        // Canonicalize root directory for consistent path handling
        let canonical_root = root.canonicalize().map_err(|e| {
            HashUtilityError::from_io_error(e, "scanning directory", Some(root.to_path_buf()))
        })?;

        // Get absolute path of output file to exclude it from scan
        // We need to get the absolute path before the file exists
        let output_absolute = if output.is_absolute() {
            output.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(output))
                .unwrap_or_else(|_| output.to_path_buf())
        };
        let excluded_output_absolute = self.excluded_output.as_ref().map(|path| {
            if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir()
                    .map(|cwd| cwd.join(path))
                    .unwrap_or_else(|_| path.clone())
            }
        });

        // Collect all files in the directory tree (only for sequential mode)
        println!("Scanning directory: {}", root.display());
        let files = if !self.parallel {
            let mut files = sequential::collect_files_with_exclusion(
                self.use_ignore,
                root,
                Some(&output_absolute),
            )?;
            if let Some(excluded) = excluded_output_absolute
                .as_ref()
                .and_then(|path| path.canonicalize().ok())
            {
                files.retain(|path| path.canonicalize().ok().as_ref() != Some(&excluded));
            }
            files
        } else {
            // For parallel mode, we don't pre-collect files
            Vec::new()
        };

        if !self.parallel {
            println!("Found {} files to process", files.len());
        }

        if self.fast_mode {
            println!("Fast mode enabled: sampling first, middle, and last 100MB of large files");
        }

        if self.parallel {
            parallel::scan_parallel(
                self.format,
                self.fast_mode,
                self.use_ignore,
                algorithm,
                output,
                &canonical_root,
                &output_absolute,
                excluded_output_absolute.as_deref(),
                start_time,
            )
        } else {
            sequential::scan_sequential(
                &self.computer,
                self.format,
                self.fast_mode,
                &files,
                algorithm,
                output,
                &canonical_root,
                start_time,
            )
        }
    }

    /// Walk directory using jwalk and send file paths to channel as they're discovered
    pub fn walk_directory_streaming(
        root: &Path,
        sender: Sender<PathBuf>,
        use_ignore: bool,
        exclude_file: Option<&Path>,
        additional_exclude_file: Option<&Path>,
        total_files_discovered: Arc<Mutex<usize>>,
    ) -> Result<(), ScanError> {
        parallel::walk_directory_streaming(
            root,
            sender,
            use_ignore,
            exclude_file,
            additional_exclude_file,
            total_files_discovered,
        )
    }

    /// Helper function for backward compatibility
    #[allow(dead_code)]
    fn collect_files(&self, root: &Path) -> Result<Vec<PathBuf>, ScanError> {
        sequential::collect_files_with_exclusion(self.use_ignore, root, None)
    }

    /// Helper function for backward compatibility
    #[allow(dead_code)]
    fn collect_files_with_exclusion(
        &self,
        root: &Path,
        exclude_file: Option<&Path>,
    ) -> Result<Vec<PathBuf>, ScanError> {
        sequential::collect_files_with_exclusion(self.use_ignore, root, exclude_file)
    }
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}
