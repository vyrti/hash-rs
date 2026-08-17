use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use crate::error::HashUtilityError;
use crate::hash::{Algorithm, DigestValue, HashMode};
use crate::manifest::{Manifest, ManifestEntry};
use crate::operation::FailurePolicy;

use super::{DatabaseEntry, DatabaseFormat, DatabaseIssue, ManifestRead};

/// Detect the format of a database file by reading its first few lines
pub fn detect_format(path: &Path) -> Result<DatabaseFormat, HashUtilityError> {
    let reader = super::compression::open_database_reader(path)?;

    for line_result in reader.lines().take(10) {
        let line = line_result.map_err(|e| {
            HashUtilityError::from_io_error(e, "reading database", Some(path.to_path_buf()))
        })?;

        let trimmed = line.trim();

        // Skip empty lines
        if trimmed.is_empty() {
            continue;
        }

        // Check for hashdeep header (starts with %)
        if trimmed.starts_with('%') {
            return Ok(DatabaseFormat::Hashdeep);
        }

        // Prefer a valid QuicHash row so a comma in its filename does not
        // incorrectly select the hashdeep parser.
        if super::quichash::parse_line(trimmed).is_some() {
            return Ok(DatabaseFormat::Quichash);
        }

        if super::hashdeep::parse_hashdeep_record(trimmed, None).is_some() {
            return Ok(DatabaseFormat::Hashdeep);
        }

        if trimmed.contains("  ") {
            return Ok(DatabaseFormat::Quichash);
        }
    }

    // Default to QuicHash format if we can't determine
    Ok(DatabaseFormat::Quichash)
}

/// Read a hash database file and parse it into a HashMap
/// Maps file paths to their database entries (hash, algorithm, fast_mode)
/// Malformed lines are skipped with a warning to stderr
/// Auto-detects format (QuicHash or hashdeep)
pub fn read_database(path: &Path) -> Result<HashMap<PathBuf, DatabaseEntry>, HashUtilityError> {
    let format = detect_format(path)?;

    match format {
        DatabaseFormat::Quichash => super::quichash::read_standard_database(path),
        DatabaseFormat::Hashdeep => super::hashdeep::read_hashdeep_database(path),
    }
}

/// Read every digest from a QuicHash or hashdeep manifest.
///
/// Format is detected automatically. This method is fail-fast; use
/// [`read_manifest_with_policy`] to retain malformed-line issues.
pub fn read_manifest(path: &Path) -> Result<Manifest, HashUtilityError> {
    Ok(read_manifest_with_policy(path, FailurePolicy::FailFast)?.manifest)
}

/// Read a typed manifest, optionally retaining malformed-line issues.
///
/// QuicHash rows for the same path are merged, and every declared hashdeep
/// digest column is retained. The returned manifest is canonicalized.
pub fn read_manifest_with_policy(
    path: &Path,
    failure_policy: FailurePolicy,
) -> Result<ManifestRead, HashUtilityError> {
    use std::collections::BTreeMap;

    let format = detect_format(path)?;
    let reader = super::compression::open_database_reader(path)?;
    let mut entries: BTreeMap<PathBuf, ManifestEntry> = BTreeMap::new();
    let mut issues = Vec::new();
    let mut hashdeep_algorithms = Vec::new();
    for (index, line_result) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line_result.map_err(|error| {
            HashUtilityError::from_io_error(error, "reading database", Some(path.to_owned()))
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("##") {
            continue;
        }
        if format == DatabaseFormat::Hashdeep && trimmed.starts_with("%%%%") {
            if let Some(fields) = trimmed.split_whitespace().find(|field| field.contains(',')) {
                let columns: Vec<_> = fields.split(',').collect();
                if columns.len() >= 3 && columns[0] == "size" && columns.last() == Some(&"filename")
                {
                    hashdeep_algorithms = columns[1..columns.len() - 1]
                        .iter()
                        .map(|name| name.parse::<Algorithm>())
                        .collect::<Result<Vec<_>, _>>()?;
                }
            }
            continue;
        }
        if trimmed.starts_with('%') || trimmed.starts_with('#') {
            continue;
        }
        let parsed = match format {
            DatabaseFormat::Quichash => super::quichash::parse_manifest_standard(&line),
            DatabaseFormat::Hashdeep => {
                super::hashdeep::parse_manifest_hashdeep(&line, &hashdeep_algorithms)
            }
        };
        match parsed {
            Ok((path, size, mode, digests)) => {
                let entry = entries
                    .entry(path.clone())
                    .or_insert_with(|| ManifestEntry {
                        relative_path: path,
                        size,
                        mode,
                        digests: Vec::new(),
                    });
                if entry.size == 0 {
                    entry.size = size;
                }
                for digest in digests {
                    if let Some(existing) = entry
                        .digests
                        .iter_mut()
                        .find(|item| item.algorithm == digest.algorithm)
                    {
                        *existing = digest;
                    } else {
                        entry.digests.push(digest);
                    }
                }
            }
            Err(reason) if failure_policy == FailurePolicy::Continue => {
                issues.push(DatabaseIssue {
                    line: line_number,
                    message: reason,
                });
            }
            Err(reason) => {
                return Err(HashUtilityError::DatabaseParseError {
                    path: path.to_owned(),
                    line: line_number,
                    reason,
                });
            }
        }
    }
    let mut manifest = Manifest {
        entries: entries.into_values().collect(),
    };
    manifest.canonicalize();
    Ok(ManifestRead { manifest, issues })
}

/// Write every manifest digest in QuicHash or hashdeep format.
///
/// QuicHash output contains one row per digest. Hashdeep output contains
/// one row per file and a column for every algorithm present in the
/// manifest.
pub fn write_manifest(
    writer: &mut impl Write,
    manifest: &Manifest,
    format: DatabaseFormat,
) -> std::io::Result<()> {
    let mut manifest = manifest.clone();
    manifest.canonicalize();
    match format {
        DatabaseFormat::Quichash => {
            for entry in &manifest.entries {
                for digest in &entry.digests {
                    super::quichash::write_entry(
                        writer,
                        &digest.to_hex(),
                        digest.algorithm.canonical_name(),
                        entry.mode == HashMode::Sampled,
                        &entry.relative_path,
                    )?;
                }
            }
        }
        DatabaseFormat::Hashdeep => {
            let mut algorithms: Vec<_> = manifest
                .entries
                .iter()
                .flat_map(|entry| entry.digests.iter().map(|digest| digest.algorithm))
                .collect();
            algorithms.sort();
            algorithms.dedup();
            let names: Vec<_> = algorithms
                .iter()
                .map(|algorithm| algorithm.canonical_name().to_owned())
                .collect();
            super::hashdeep::write_hashdeep_header(writer, &names)?;
            for entry in &manifest.entries {
                let hashes: Vec<_> = algorithms
                    .iter()
                    .map(|algorithm| {
                        entry
                            .digests
                            .iter()
                            .find(|digest| digest.algorithm == *algorithm)
                            .map(DigestValue::to_hex)
                            .unwrap_or_default()
                    })
                    .collect();
                super::hashdeep::write_hashdeep_entry(
                    writer,
                    entry.size,
                    &hashes,
                    &entry.relative_path,
                )?;
            }
        }
    }
    Ok(())
}

/// Write a manifest to its canonical database path.
///
/// The returned path is the actual file created. Compressed output is
/// written first as a plain `.qh` file and removed only after the `.qh.xz`
/// file has been completed successfully. This leaves the readable plain
/// database in place if compression fails.
pub fn write_manifest_file(
    requested_path: &Path,
    manifest: &Manifest,
    format: DatabaseFormat,
    compressed: bool,
) -> Result<PathBuf, HashUtilityError> {
    // Validate the combination before creating a file.
    let final_path = super::compression::canonical_output_path(requested_path, format, compressed)?;
    let plain_path = super::compression::canonical_output_path(requested_path, format, false)?;
    let mut file = File::create(&plain_path).map_err(|error| {
        HashUtilityError::from_io_error(error, "creating database", Some(plain_path.clone()))
    })?;
    write_manifest(&mut file, manifest, format).map_err(|error| {
        HashUtilityError::from_io_error(error, "writing database", Some(plain_path.clone()))
    })?;
    file.flush().map_err(|error| {
        HashUtilityError::from_io_error(error, "flushing database", Some(plain_path.clone()))
    })?;
    drop(file);

    if !compressed {
        return Ok(plain_path);
    }

    let compressed_path = super::compression::compress_database(&plain_path)?;
    debug_assert_eq!(compressed_path, final_path);
    std::fs::remove_file(&plain_path).map_err(|error| {
        HashUtilityError::from_io_error(error, "removing uncompressed database", Some(plain_path))
    })?;
    Ok(compressed_path)
}
