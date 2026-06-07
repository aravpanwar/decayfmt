//! All error types for decayfmt.
//!
//! Every error variant that any module can produce lives here, defined once as a
//! single complete error model. Each variant names the component, the operation,
//! and the condition that failed, so a failure is understandable without reading
//! the source. Errors are returned from library functions, never printed; the CLI
//! layer is responsible for printing them.

use std::fmt;

/// The four magic bytes every decayfmt file must begin with.
/// Repeated from format.rs intentionally so error messages can report what was
/// expected without depending on format.rs internals.
const EXPECTED_MAGIC: &[u8; 4] = b"DCYF";

/// The complete set of failures decayfmt can produce.
///
/// Some variants are produced by modules built in later milestones (encode, open).
/// They are declared here now because the error model is a single deliverable: the
/// full contract of how decayfmt fails is fixed up front, not grown ad hoc. The
/// allow below acknowledges that not every variant is constructed yet.
#[allow(dead_code)]
#[derive(Debug)]
pub enum DecayError {
    /// The file did not start with the magic bytes DCYF. The file is not a
    /// decayfmt file and must not be parsed any further.
    WrongMagic { found: [u8; 4] },

    /// The version byte is not a version this build understands. We never guess
    /// at forward compatibility; an unknown version is a hard refusal.
    UnsupportedVersion { found: u8 },

    /// The file_type byte is neither image (0x01) nor text (0x02).
    UnsupportedFileType { found: u8 },

    /// The target file is read-only. Corruption cannot be written, so the file is
    /// not displayed. Opening must cost a corruption; a free read breaks the contract.
    ReadOnly { path: String },

    /// The buffer is shorter than the fixed 16-byte header, so no valid header
    /// could be read from it.
    PayloadTooSmall { found: usize, needed: usize },

    /// A text payload did not contain valid UTF-8 where valid UTF-8 was required.
    InvalidUtf8,

    /// The filename contained no parseable instability value x. x is read from the
    /// filename and nowhere else, so without it the file cannot be opened.
    FilenameNoX { filename: String },

    /// The instability value x parsed from the filename was not a positive number.
    XNotPositive { value: f64 },
}

impl fmt::Display for DecayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecayError::WrongMagic { found } => write!(
                f,
                "format: magic check failed: expected {:?} (DCYF), found {:?}. This is not a decayfmt file.",
                EXPECTED_MAGIC, found
            ),
            DecayError::UnsupportedVersion { found } => write!(
                f,
                "format: version check failed: version 0x{:02x} is not supported by this build. Refusing to guess at forward compatibility.",
                found
            ),
            DecayError::UnsupportedFileType { found } => write!(
                f,
                "format: file_type check failed: 0x{:02x} is neither image (0x01) nor text (0x02).",
                found
            ),
            DecayError::ReadOnly { path } => write!(
                f,
                "open: writability check failed: '{}' is read-only. Corruption cannot be written, so the file will not be displayed.",
                path
            ),
            DecayError::PayloadTooSmall { found, needed } => write!(
                f,
                "format: header read failed: buffer is {} bytes but the header needs {} bytes.",
                found, needed
            ),
            DecayError::InvalidUtf8 => write!(
                f,
                "encode: text read failed: source is not valid UTF-8."
            ),
            DecayError::FilenameNoX { filename } => write!(
                f,
                "open: filename parse failed: '{}' contains no positive instability value x in its extension.",
                filename
            ),
            DecayError::XNotPositive { value } => write!(
                f,
                "open: instability check failed: x = {} is not a positive number.",
                value
            ),
        }
    }
}

impl std::error::Error for DecayError {}
