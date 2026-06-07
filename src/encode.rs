//! Encode a source file into a decayfmt file.
//!
//! This module reads a source image or text file, builds the fixed header via
//! format.rs, and writes the header followed by the raw, uncorrupted payload. The
//! invariant it upholds is that encoding never corrupts: a freshly encoded file is
//! clean. Corruption only ever happens at open time, in open.rs. All file I/O for
//! the encode flow lives here.

use crate::error::DecayError;
use crate::format::{FileType, Header};
use std::fs;
use std::path::Path;

/// Validates that the instability value x supplied for encoding is usable.
///
/// x must be a positive, finite number. Zero, negatives, infinities, and NaN are
/// all refused with XNotPositive. This is the single place x is checked at encode
/// time; the rest of the flow can assume a sane x once this returns Ok.
fn validate_x(x: f64) -> Result<(), DecayError> {
    if x.is_finite() && x > 0.0 {
        Ok(())
    } else {
        Err(DecayError::XNotPositive { value: x })
    }
}

/// Determines the payload type from the output filename's extension.
///
/// The decayfmt naming convention is `name.idcy<x>` for images and `name.tdcy<x>`
/// for text, where the same extension later carries x at open time. The numeric
/// suffix is ignored here because x is supplied explicitly via the CLI at encode;
/// only the idcy/tdcy prefix decides the file type. An unrecognized extension is
/// refused rather than guessed.
fn file_type_from_output(output: &Path) -> Result<FileType, DecayError> {
    let extension = output
        .extension()
        .and_then(|raw| raw.to_str())
        .unwrap_or("");
    if extension.starts_with("idcy") {
        Ok(FileType::Image)
    } else if extension.starts_with("tdcy") {
        Ok(FileType::Text)
    } else {
        Err(DecayError::UnrecognizedExtension {
            extension: extension.to_string(),
        })
    }
}

/// Decodes a source image's bytes into a raw RGBA payload.
///
/// The image crate accepts any format it supports (PNG, JPEG, and others) and is
/// reduced here to raw RGBA, four bytes per pixel, which is exactly what the
/// decayfmt payload stores. The payload is the pixel data only; width and height
/// are not part of it and, in the current header layout, are not stored anywhere.
fn image_payload(source_bytes: &[u8], input: &Path) -> Result<Vec<u8>, DecayError> {
    let decoded = image::load_from_memory(source_bytes).map_err(|error| DecayError::ImageDecode {
        context: format!("encode: decode image '{}': {}", input.display(), error),
    })?;
    Ok(decoded.to_rgba8().into_raw())
}

/// Produces a raw text payload from source bytes, requiring valid UTF-8.
///
/// The payload is stored as raw UTF-8 bytes exactly as read. Invalid UTF-8 is
/// refused at encode time so that only well-formed text ever enters the format;
/// the later corruption at open time is what may break that validity.
fn text_payload(source_bytes: Vec<u8>) -> Result<Vec<u8>, DecayError> {
    match std::str::from_utf8(&source_bytes) {
        Ok(_) => Ok(source_bytes),
        Err(_) => Err(DecayError::InvalidUtf8),
    }
}

/// Writes the header and raw payload to the output path as a single file.
///
/// The header is written exactly once, here, and is never rewritten afterward.
/// The payload follows immediately after the fixed 16-byte header.
fn write_decayfmt(output: &Path, header: Header, payload: &[u8]) -> Result<(), DecayError> {
    let header_bytes = header.write();
    let mut file_bytes = Vec::with_capacity(header_bytes.len() + payload.len());
    file_bytes.extend_from_slice(&header_bytes);
    file_bytes.extend_from_slice(payload);
    fs::write(output, &file_bytes).map_err(|error| DecayError::Io {
        context: format!("encode: write output '{}'", output.display()),
        source: error,
    })
}

/// Encodes a source file at `input` into a decayfmt file at `output` for the given
/// instability value x.
///
/// The file type is taken from the output extension, the source is read and turned
/// into a raw payload (RGBA for images, UTF-8 for text), and the header plus
/// payload are written out. No corruption is applied; the produced file is clean
/// and will parse cleanly via format.rs.
pub fn encode_file(input: &Path, output: &Path, x: f64) -> Result<(), DecayError> {
    validate_x(x)?;
    let file_type = file_type_from_output(output)?;

    let source_bytes = fs::read(input).map_err(|error| DecayError::Io {
        context: format!("encode: read input '{}'", input.display()),
        source: error,
    })?;

    let payload = match file_type {
        FileType::Image => image_payload(&source_bytes, input)?,
        FileType::Text => text_payload(source_bytes)?,
    };

    write_decayfmt(output, Header::new(file_type), &payload)
}
