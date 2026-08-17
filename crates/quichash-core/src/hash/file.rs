use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

use super::algorithm::{Algorithm, DigestValue, HashMode};
use super::hasher::HasherSet;
use crate::error::HashUtilityError;

// Constants for fast mode sampling
pub(crate) const FAST_MODE_SAMPLE_SIZE: u64 = 100 * 1024 * 1024; // 100MB
pub(crate) const FAST_MODE_THRESHOLD: u64 = 3 * FAST_MODE_SAMPLE_SIZE; // 300MB

// Constants for memory mapping
#[cfg(feature = "mmap")]
pub(crate) const MMAP_THRESHOLD: u64 = 2 * 1024 * 1024 * 1024; // 2GB

// Constants for progress bar
pub(crate) const PROGRESS_BAR_THRESHOLD: u64 = 1024 * 1024 * 1024; // 1GB
pub(crate) const PROGRESS_UPDATE_INTERVAL_MS: u64 = 100; // 10 times per second

/// Hash an in-memory byte slice with one or more algorithms.
///
/// The input is presented to every algorithm once, and results preserve the
/// requested order.
pub fn hash_bytes(
    data: &[u8],
    algorithms: &[Algorithm],
) -> Result<Vec<DigestValue>, HashUtilityError> {
    let mut hashers = HasherSet::new(algorithms)?;
    hashers.update(data);
    Ok(hashers.finalize())
}

/// Stream a reader through one or more algorithms.
///
/// This convenience function uses a 1 MiB internal buffer and no observer.
pub fn hash_reader(
    mut reader: impl Read,
    algorithms: &[Algorithm],
) -> Result<Vec<DigestValue>, HashUtilityError> {
    hash_reader_observed(&mut reader, algorithms, &crate::operation::NoopObserver)
}

/// Stream a reader while reporting byte progress and checking cancellation.
///
/// Progress has no known total because a generic reader does not expose its
/// length. The observer is checked before every read.
pub fn hash_reader_observed(
    mut reader: impl Read,
    algorithms: &[Algorithm],
    observer: &dyn crate::operation::OperationObserver,
) -> Result<Vec<DigestValue>, HashUtilityError> {
    let mut hashers = HasherSet::new(algorithms)?;
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut bytes_processed = 0_u64;
    loop {
        if observer.is_cancelled() {
            return Err(HashUtilityError::Cancelled);
        }
        let amount = reader.read(&mut buffer)?;
        if amount == 0 {
            break;
        }
        hashers.update(&buffer[..amount]);
        bytes_processed += amount as u64;
        observer.on_progress(&crate::operation::ProgressEvent {
            phase: crate::operation::ProgressPhase::Hashing,
            completed: bytes_processed,
            total: None,
            bytes_processed,
            path: None,
        });
    }
    Ok(hashers.finalize())
}

/// Hash the complete contents of a file with one or more algorithms.
///
/// A single BLAKE3 digest uses its memory-mapped parallel implementation when
/// the `blake3`, `parallel`, and `mmap` features are enabled.
pub fn hash_file(
    path: &Path,
    algorithms: &[Algorithm],
) -> Result<Vec<DigestValue>, HashUtilityError> {
    #[cfg(all(feature = "blake3", feature = "parallel", feature = "mmap"))]
    if algorithms == [Algorithm::Blake3] {
        let mut hasher = super::hasher::Blake3Hasher::new();
        hasher.update_mmap_rayon(path).map_err(|error| {
            HashUtilityError::from_io_error(error, "reading", Some(path.to_owned()))
        })?;
        return Ok(vec![DigestValue {
            algorithm: Algorithm::Blake3,
            bytes: hasher.finalize().as_bytes().to_vec(),
        }]);
    }
    let file = File::open(path).map_err(|error| {
        HashUtilityError::from_io_error(error, "reading", Some(path.to_owned()))
    })?;
    hash_reader(file, algorithms)
}

/// Hash a file in full or sampled mode.
///
/// Files smaller than the sampling threshold are read completely even in
/// [`HashMode::Sampled`]. Larger files hash 100 MiB from the beginning, middle,
/// and end. Sampled hashes are for identification rather than complete
/// integrity verification.
pub fn hash_file_mode(
    path: &Path,
    algorithms: &[Algorithm],
    mode: HashMode,
) -> Result<Vec<DigestValue>, HashUtilityError> {
    if mode == HashMode::Full {
        return hash_file(path, algorithms);
    }
    let mut file = File::open(path).map_err(|error| {
        HashUtilityError::from_io_error(error, "reading", Some(path.to_owned()))
    })?;
    let size = file
        .metadata()
        .map_err(|error| {
            HashUtilityError::from_io_error(error, "reading metadata", Some(path.to_owned()))
        })?
        .len();
    if size < FAST_MODE_THRESHOLD {
        return hash_reader(file, algorithms);
    }
    let mut hashers = HasherSet::new(algorithms)?;
    for start in [
        0,
        (size / 2).saturating_sub(FAST_MODE_SAMPLE_SIZE / 2),
        size.saturating_sub(FAST_MODE_SAMPLE_SIZE),
    ] {
        file.seek(std::io::SeekFrom::Start(start))
            .map_err(|error| {
                HashUtilityError::from_io_error(error, "seeking", Some(path.to_owned()))
            })?;
        let mut remaining = FAST_MODE_SAMPLE_SIZE;
        let mut buffer = vec![0_u8; 1024 * 1024];
        while remaining > 0 {
            let wanted = remaining.min(buffer.len() as u64) as usize;
            let amount = file.read(&mut buffer[..wanted]).map_err(|error| {
                HashUtilityError::from_io_error(error, "reading", Some(path.to_owned()))
            })?;
            if amount == 0 {
                break;
            }
            hashers.update(&buffer[..amount]);
            remaining -= amount as u64;
        }
    }
    Ok(hashers.finalize())
}
