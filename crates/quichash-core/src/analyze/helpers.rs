use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::report::{DuplicateGroup, EntryWithSize};
use crate::database::{DatabaseFormat, DatabaseHandler};
use crate::error::HashUtilityError;

/// Read database and extract size information if available
pub(crate) fn read_database_with_sizes(
    path: &Path,
    format: DatabaseFormat,
) -> Result<HashMap<PathBuf, EntryWithSize>, HashUtilityError> {
    match format {
        DatabaseFormat::Quichash => {
            // QuicHash format doesn't have sizes
            let db = DatabaseHandler::read_database(path)?;
            Ok(db
                .into_iter()
                .map(|(path, entry)| {
                    (
                        path,
                        EntryWithSize {
                            hash: entry.hash,
                            algorithm: entry.algorithm,
                            fast_mode: entry.fast_mode,
                            file_size: None,
                        },
                    )
                })
                .collect())
        }
        DatabaseFormat::Hashdeep => {
            // Parse hashdeep format with sizes
            read_hashdeep_with_sizes(path)
        }
    }
}

/// Read hashdeep format database and extract file sizes
pub(crate) fn read_hashdeep_with_sizes(
    path: &Path,
) -> Result<HashMap<PathBuf, EntryWithSize>, HashUtilityError> {
    use std::io::BufRead;

    let file = std::fs::File::open(path).map_err(|e| {
        HashUtilityError::from_io_error(e, "opening database", Some(path.to_path_buf()))
    })?;

    let reader: Box<dyn BufRead> = if DatabaseHandler::is_compressed(path) {
        #[cfg(feature = "xz")]
        {
            Box::new(std::io::BufReader::new(xz2::read::XzDecoder::new(file)))
        }
        #[cfg(not(feature = "xz"))]
        {
            let _ = file;
            return Err(HashUtilityError::InvalidArguments {
                message: format!(
                    "reading '{}' requires the 'xz' Cargo feature",
                    path.display()
                ),
            });
        }
    } else {
        Box::new(std::io::BufReader::new(file))
    };

    let mut entries = HashMap::new();
    let mut algorithms: Vec<String> = Vec::new();

    for line_result in reader.lines() {
        let line = line_result.map_err(|e| {
            HashUtilityError::from_io_error(e, "reading database", Some(path.to_path_buf()))
        })?;

        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse header to get algorithm names
        if trimmed.starts_with("%%%%") && trimmed.contains(',') {
            let header_parts: Vec<&str> = trimmed.split_whitespace().collect();
            if header_parts.len() >= 2 {
                let fields: Vec<&str> = header_parts[1].split(',').collect();
                if fields.len() >= 3 {
                    algorithms = fields[1..fields.len() - 1]
                        .iter()
                        .map(|s| s.to_string())
                        .collect();
                }
            }
            continue;
        }

        // Skip other header lines
        if trimmed.starts_with('%') {
            continue;
        }

        let expected_hash_count = (!algorithms.is_empty()).then_some(algorithms.len());
        let Some(record) = DatabaseHandler::parse_hashdeep_record(&line, expected_hash_count)
        else {
            continue;
        };

        // Use the first digest for compatibility with the analysis engine.
        let hash = &record.hashes[0];
        if hash.is_empty() {
            continue;
        }

        let algorithm = algorithms
            .first()
            .cloned()
            .unwrap_or_else(|| infer_algorithm_from_hash(hash));

        let file_path = crate::path_utils::parse_database_path(&record.filename);
        entries.insert(
            file_path,
            EntryWithSize {
                hash: hash.clone(),
                algorithm,
                fast_mode: false,
                file_size: Some(record.size),
            },
        );
    }

    Ok(entries)
}

/// Find duplicate files (same hash, different paths)
pub(crate) fn find_duplicates(entries: &HashMap<PathBuf, EntryWithSize>) -> Vec<DuplicateGroup> {
    // Group paths by hash
    let mut hash_to_entries: HashMap<String, Vec<(&PathBuf, &EntryWithSize)>> = HashMap::new();

    for (path, entry) in entries {
        hash_to_entries
            .entry(entry.hash.clone())
            .or_default()
            .push((path, entry));
    }

    // Filter to only groups with duplicates
    let mut duplicates: Vec<DuplicateGroup> = hash_to_entries
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(hash, mut items)| {
            items.sort_by(|a, b| a.0.cmp(b.0));
            let count = items.len();
            let file_size = items.first().and_then(|(_, e)| e.file_size);
            let wasted_space = file_size.map(|s| s * (count as u64 - 1));

            DuplicateGroup {
                hash,
                paths: items.into_iter().map(|(p, _)| p.clone()).collect(),
                count,
                file_size,
                wasted_space,
            }
        })
        .collect();

    // Sort by wasted space (descending) then by hash
    duplicates.sort_by(|a, b| {
        b.wasted_space
            .cmp(&a.wasted_space)
            .then_with(|| a.hash.cmp(&b.hash))
    });

    duplicates
}

/// Infer hash algorithm from hash string length
pub(crate) fn infer_algorithm_from_hash(hash: &str) -> String {
    match hash.len() {
        32 => "md5".to_string(),
        40 => "sha1".to_string(),
        56 => "sha224".to_string(),
        64 => "sha256".to_string(),
        96 => "sha384".to_string(),
        128 => "sha512".to_string(),
        _ => "unknown".to_string(),
    }
}
