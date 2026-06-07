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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{FILE_TYPE_TEXT, HEADER_SIZE, MAGIC, VERSION};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Builds a unique path in the system temp directory so concurrent test runs do
    /// not collide. The suffix carries the extension the test needs.
    fn unique_temp_path(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("decayfmt_test_{}_{}", nanos, suffix))
    }

    #[test]
    fn validate_x_accepts_positive_values() {
        for x in [0.5, 1.0, 3.0, 10.0, 1000.0] {
            assert!(validate_x(x).is_ok(), "x = {} should be accepted", x);
        }
    }

    #[test]
    fn validate_x_rejects_non_positive_and_non_finite() {
        for x in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(
                matches!(validate_x(x), Err(DecayError::XNotPositive { .. })),
                "x = {} should be rejected with XNotPositive",
                x
            );
        }
    }

    #[test]
    fn file_type_is_detected_from_output_extension() {
        assert_eq!(
            file_type_from_output(Path::new("photo.idcy3")).expect("idcy is an image"),
            FileType::Image
        );
        assert_eq!(
            file_type_from_output(Path::new("note.tdcy7")).expect("tdcy is text"),
            FileType::Text
        );
    }

    #[test]
    fn unrecognized_output_extension_is_refused() {
        for name in ["photo.png", "note.txt", "noextension"] {
            assert!(
                matches!(
                    file_type_from_output(Path::new(name)),
                    Err(DecayError::UnrecognizedExtension { .. })
                ),
                "'{}' should be refused",
                name
            );
        }
    }

    #[test]
    fn encode_text_writes_header_and_exact_payload() {
        let source = b"the quick brown fox jumps over the lazy dog";
        let input = unique_temp_path("source.txt");
        let output = unique_temp_path("note.tdcy3");
        fs::write(&input, source).expect("write test source");

        encode_file(&input, &output, 3.0).expect("encode text should succeed");

        let written = fs::read(&output).expect("read encoded file");
        assert_eq!(&written[0..4], &MAGIC, "magic bytes must be DCYF");
        assert_eq!(written[4], VERSION, "version byte must match");
        assert_eq!(written[5], FILE_TYPE_TEXT, "file_type byte must be text");
        assert_eq!(
            &written[HEADER_SIZE..],
            source,
            "text payload must match source bytes exactly"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn encode_image_payload_length_matches_dimensions() {
        // A known 2x2 image has a payload of exactly width * height * 4 bytes.
        let width = 2u32;
        let height = 2u32;
        let source_image = image::RgbaImage::from_fn(width, height, |x, y| {
            image::Rgba([x as u8 * 10, y as u8 * 10, 20, 255])
        });
        let input = unique_temp_path("source.png");
        let output = unique_temp_path("photo.idcy3");
        source_image.save(&input).expect("save test png");

        encode_file(&input, &output, 3.0).expect("encode image should succeed");

        let written = fs::read(&output).expect("read encoded file");
        assert_eq!(&written[0..4], &MAGIC, "magic bytes must be DCYF");
        assert_eq!(written[4], VERSION, "version byte must match");
        let payload_len = written.len() - HEADER_SIZE;
        assert_eq!(
            payload_len,
            (width * height * 4) as usize,
            "image payload must be width * height * 4 bytes"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }
}
