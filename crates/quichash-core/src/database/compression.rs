use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[cfg(feature = "zstd")]
use structured_zstd::decoding::StreamingDecoder;
#[cfg(feature = "zstd")]
use structured_zstd::encoding::{CompressionLevel, StreamingEncoder};

use crate::error::HashUtilityError;

use super::DatabaseFormat;

/// Return the canonical output path for a database.
///
/// Any existing final extension is replaced. An existing `.zst` or `.zstd` suffix is
/// removed before normalization, so legacy names such as `hashes.txt.zst`
/// become `hashes.qh` or `hashes.qh.zst` according to `compressed`.
/// QuicHash databases use `.qh`, compressed QuicHash databases use
/// `.qh.zst`, and hashdeep databases use `.hashdeep`.
pub fn canonical_output_path(
    requested_path: &Path,
    format: DatabaseFormat,
    compressed: bool,
) -> Result<PathBuf, HashUtilityError> {
    if compressed && format == DatabaseFormat::Hashdeep {
        return Err(HashUtilityError::InvalidArguments {
            message: "hashdeep output cannot be compressed; use QuicHash format with --compress"
                .to_owned(),
        });
    }

    let mut output_path = requested_path.to_path_buf();
    if is_compressed(&output_path) {
        output_path.set_extension("");
    }
    output_path.set_extension(match format {
        DatabaseFormat::Quichash if compressed => "qh.zst",
        DatabaseFormat::Quichash => "qh",
        DatabaseFormat::Hashdeep => "hashdeep",
    });
    Ok(output_path)
}

/// Check if a path has .zst or .zstd extension (compressed database)
pub fn is_compressed(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("zst") || ext.eq_ignore_ascii_case("zstd"))
        .unwrap_or(false)
}

/// Compress a database file with Zstandard.
///
/// The input must contain QuicHash rows and must not already be compressed.
/// The output path is normalized to `.qh.zst`. When the `zstd` feature is
/// disabled, this returns an explanatory error. Compression failures never
/// remove the input file and clean up a newly-created partial output file.
#[cfg(feature = "zstd")]
pub fn compress_database(input_path: &Path) -> Result<PathBuf, HashUtilityError> {
    if is_compressed(input_path) {
        return Err(HashUtilityError::InvalidArguments {
            message: format!("database '{}' is already compressed", input_path.display()),
        });
    }
    if super::manifest_io::detect_format(input_path)? != DatabaseFormat::Quichash {
        return Err(HashUtilityError::InvalidArguments {
            message: format!(
                "only QuicHash databases can be compressed: '{}'",
                input_path.display()
            ),
        });
    }

    // Read the input file
    let input_file = File::open(input_path).map_err(|e| {
        HashUtilityError::from_io_error(
            e,
            "opening database for compression",
            Some(input_path.to_path_buf()),
        )
    })?;

    let output_path = canonical_output_path(input_path, DatabaseFormat::Quichash, true)?;

    // Create compressed output file
    let output_file = File::create(&output_path).map_err(|e| {
        HashUtilityError::from_io_error(
            e,
            "creating compressed database",
            Some(output_path.clone()),
        )
    })?;

    // Create Zstandard encoder with default compression level (3)
    let mut encoder = StreamingEncoder::new(output_file, CompressionLevel::from_level(3));

    // Copy data through the encoder
    let mut reader = BufReader::new(input_file);
    let compression_result = (|| {
        std::io::copy(&mut reader, &mut encoder).map_err(|e| {
            HashUtilityError::from_io_error(
                e,
                "compressing database",
                Some(input_path.to_path_buf()),
            )
        })?;

        encoder.finish().map_err(|e| {
            HashUtilityError::from_io_error(
                std::io::Error::other(e.to_string()),
                "finalizing compression",
                Some(output_path.clone()),
            )
        })?;
        Ok::<(), HashUtilityError>(())
    })();
    if let Err(error) = compression_result {
        let _ = std::fs::remove_file(&output_path);
        return Err(error);
    }

    Ok(output_path)
}

#[cfg(not(feature = "zstd"))]
/// Return an error explaining that Zstandard support was compiled out.
pub fn compress_database(input_path: &Path) -> Result<PathBuf, HashUtilityError> {
    Err(HashUtilityError::InvalidArguments {
        message: format!(
            "Zstandard compression for '{}' requires the 'zstd' Cargo feature",
            input_path.display()
        ),
    })
}

/// Open a database file, automatically decompressing if it has .zst / .zstd extension
pub(crate) fn open_database_reader(path: &Path) -> Result<Box<dyn BufRead>, HashUtilityError> {
    let file = File::open(path).map_err(|e| {
        HashUtilityError::from_io_error(e, "opening database", Some(path.to_path_buf()))
    })?;

    if is_compressed(path) {
        #[cfg(feature = "zstd")]
        {
            let decoder = StreamingDecoder::new(BufReader::new(file)).map_err(|e| {
                HashUtilityError::from_io_error(
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
                    "opening compressed database",
                    Some(path.to_path_buf()),
                )
            })?;
            Ok(Box::new(BufReader::new(decoder)))
        }
        #[cfg(not(feature = "zstd"))]
        {
            let _ = file;
            Err(HashUtilityError::InvalidArguments {
                message: format!(
                    "reading '{}' requires the 'zstd' Cargo feature",
                    path.display()
                ),
            })
        }
    } else {
        // Read normally
        Ok(Box::new(BufReader::new(file)))
    }
}
