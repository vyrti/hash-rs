use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::error::HashUtilityError;
use crate::hash::{Algorithm, DigestValue, HashMode};
use crate::manifest::{Manifest, ManifestEntry};

pub(crate) fn checksum_algorithm_from_path(path: &Path) -> Option<Algorithm> {
    let mut algorithm_path = path.to_path_buf();
    if super::compression::is_compressed(&algorithm_path) {
        algorithm_path.set_extension("");
    }
    let extension = algorithm_path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "md5" => Some(Algorithm::Md5),
        "sha1" | "sha-1" => Some(Algorithm::Sha1),
        "sha224" | "sha-224" => Some(Algorithm::Sha224),
        "sha256" | "sha-256" => Some(Algorithm::Sha256),
        "sha384" | "sha-384" => Some(Algorithm::Sha384),
        "sha512" | "sha-512" => Some(Algorithm::Sha512),
        "sha3-224" => Some(Algorithm::Sha3_224),
        "sha3-256" => Some(Algorithm::Sha3_256),
        "sha3-384" => Some(Algorithm::Sha3_384),
        "sha3-512" => Some(Algorithm::Sha3_512),
        "blake2b" | "blake2b-512" => Some(Algorithm::Blake2b512),
        "blake2s" | "blake2s-256" => Some(Algorithm::Blake2s256),
        "blake3" => Some(Algorithm::Blake3),
        "xxh3" => Some(Algorithm::Xxh3),
        "xxh128" => Some(Algorithm::Xxh128),
        _ => None,
    }
}

pub(crate) fn verification_checksum_algorithm(
    path: &Path,
) -> Result<Option<Algorithm>, HashUtilityError> {
    if let Some(algorithm) = checksum_algorithm_from_path(path) {
        return Ok(Some(algorithm));
    }

    let reader = super::compression::open_database_reader(path)?;
    for line_result in reader.lines() {
        let line = line_result.map_err(|error| {
            HashUtilityError::from_io_error(error, "reading checksum file", Some(path.to_owned()))
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('%')
            || super::quichash::parse_line(trimmed).is_some()
            || super::hashdeep::parse_hashdeep_record(trimmed, None).is_some()
        {
            return Ok(None);
        }
        let candidate = trimmed.strip_prefix('\\').unwrap_or(trimmed);
        let looks_like_checksum = candidate
            .find(|character: char| character.is_ascii_whitespace())
            .is_some_and(|index| {
                index > 0
                    && candidate[..index]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    && !candidate[index..].trim().is_empty()
            });
        if looks_like_checksum {
            return Err(HashUtilityError::InvalidArguments {
                message: format!(
                    "cannot infer checksum algorithm from extension of '{}'",
                    path.display()
                ),
            });
        }
        return Ok(None);
    }
    Ok(None)
}

/// Read a conventional two-column checksum file for verification.
///
/// The algorithm is inferred from the filename extension. GNU text and
/// binary markers, generic whitespace-separated rows, comments, CRLF, and
/// GNU escaped filenames are supported. Parsing is strict: every usable
/// row must be valid and the file must contain at least one entry.
pub fn read_checksum_manifest(path: &Path) -> Result<Manifest, HashUtilityError> {
    let algorithm =
        checksum_algorithm_from_path(path).ok_or_else(|| HashUtilityError::InvalidArguments {
            message: format!(
                "cannot infer checksum algorithm from extension of '{}'",
                path.display()
            ),
        })?;
    let reader = super::compression::open_database_reader(path)?;
    let mut entries: BTreeMap<PathBuf, ManifestEntry> = BTreeMap::new();
    let mut usable_rows = 0usize;
    for (index, line_result) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line_result.map_err(|error| {
            HashUtilityError::from_io_error(error, "reading checksum file", Some(path.to_owned()))
        })?;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let (relative_path, digest) = parse_checksum_line(&line, algorithm).map_err(|reason| {
            HashUtilityError::DatabaseParseError {
                path: path.to_owned(),
                line: line_number,
                reason,
            }
        })?;
        usable_rows += 1;
        let entry = entries
            .entry(relative_path.clone())
            .or_insert_with(|| ManifestEntry {
                relative_path,
                size: 0,
                mode: HashMode::Full,
                digests: Vec::new(),
            });
        if let Some(existing) = entry
            .digests
            .iter_mut()
            .find(|item| item.algorithm == algorithm)
        {
            *existing = digest;
        } else {
            entry.digests.push(digest);
        }
    }
    if usable_rows == 0 {
        return Err(HashUtilityError::EmptyDatabase {
            path: path.to_owned(),
        });
    }
    let mut manifest = Manifest {
        entries: entries.into_values().collect(),
    };
    manifest.canonicalize();
    Ok(manifest)
}

fn parse_checksum_line(line: &str, algorithm: Algorithm) -> Result<(PathBuf, DigestValue), String> {
    let (escaped, content) = match line.strip_prefix('\\') {
        Some(content) => (true, content),
        None => (false, line),
    };
    let separator = content
        .find(|character: char| character.is_ascii_whitespace())
        .ok_or_else(|| "expected '<hash> <filename>'".to_owned())?;
    let hash = &content[..separator];
    let remainder = &content[separator..];
    let filename = if let Some(filename) = remainder.strip_prefix(" *") {
        filename
    } else {
        remainder.trim_start_matches(|character: char| character.is_ascii_whitespace())
    };
    if filename.is_empty() {
        return Err("checksum row contains an empty filename".to_owned());
    }
    if filename.contains('\0') {
        return Err("NUL-delimited checksum files are not supported".to_owned());
    }
    let filename = if escaped {
        decode_gnu_checksum_filename(filename)?
    } else {
        filename.to_owned()
    };
    let digest = DigestValue::from_hex(algorithm, hash).map_err(|error| error.to_string())?;
    Ok((PathBuf::from(filename), digest))
}

fn decode_gnu_checksum_filename(filename: &str) -> Result<String, String> {
    let mut decoded = String::with_capacity(filename.len());
    let mut characters = filename.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('\\') => decoded.push('\\'),
            Some('n') => decoded.push('\n'),
            Some(other) => {
                return Err(format!("unsupported GNU filename escape '\\{other}'"));
            }
            None => return Err("GNU escaped filename ends with a backslash".to_owned()),
        }
    }
    Ok(decoded)
}
