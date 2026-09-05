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
/// The full contract of how decayfmt fails lives in one place: every error any
/// module returns is a variant here, each naming the component, operation, and
/// condition that failed.
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

    /// The filename's extension prefix and the header disagree about the payload
    /// type, for example an image file renamed to a `.tdcy<x>` name. We refuse
    /// rather than trust one source over the other.
    MismatchedFileType {
        extension_kind: &'static str,
        header_kind: &'static str,
    },

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

    /// The instability value x in the filename was a run of digits too large to fit
    /// a u32. There is an x; it is simply out of the supported range.
    XOutOfRange { value: String },

    /// A filesystem read or write failed. The context names the component and the
    /// operation; the source is the underlying operating system error.
    Io {
        context: String,
        source: std::io::Error,
    },

    /// The source given to encode could not be decoded as a supported image. The
    /// context carries the underlying decoder message, kept as a string so this
    /// error type stays free of any image-crate dependency.
    ImageDecode { context: String },

    /// The output filename for encode had an extension that is neither an image
    /// (idcy) nor a text (tdcy) decayfmt extension, so the file type is unknown.
    UnrecognizedExtension { extension: String },

    /// On open, the image payload length did not match the width and height in the
    /// header, so the bytes cannot be interpreted as a complete image. The file is
    /// truncated or otherwise inconsistent with its own header.
    PayloadSizeMismatch { expected: usize, found: usize },

    /// On open, the corrupted image could not be re-encoded for display. The context
    /// carries the underlying encoder message as a string.
    ImageEncode { context: String },

    /// A v2 header is internally inconsistent or out of range: a field combination
    /// that violates the v2 format invariants, for example an unbound header carrying
    /// sealed blobs, a bound header carrying a wrapped key, or a field that must be
    /// non-zero (like a bound header's `nv_index`) that is zero.
    InvalidHeaderV2 { reason: String },

    /// A cryptographic primitive failed: key derivation, key wrapping, or AEAD
    /// encryption/decryption. Authentication failures (wrong passphrase/key, tampered
    /// ciphertext, mismatched AAD) surface here rather than panicking.
    Crypto { context: String },

    /// A TPM operation failed: context / TCTI initialization, sealing or unsealing the
    /// content key, loading the sealed object, or generating the storage parent. The
    /// context names the operation; it never carries secret material.
    Tpm { context: String },

    /// A TPM NV counter operation failed (define/increment/read/undefine). Distinct from
    /// [`DecayError::Tpm`] so NV counter errors fail closed and are reported precisely.
    NvCounter { context: String },

    /// A caller-supplied argument is invalid: for example the `-v2` flag given for a v1
    /// (decay-suffixed) output name, or another usage error. Kept distinct from format
    /// errors so CLI/API misuse is reported precisely rather than as a malformed file.
    InvalidArgument { context: String },
}

impl fmt::Display for DecayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecayError::WrongMagic { found } => write!(
                f,
                "format: magic check failed: expected {EXPECTED_MAGIC:?} (DCYF), found {found:?}. This is not a decayfmt file."
            ),
            DecayError::UnsupportedVersion { found } => write!(
                f,
                "format: version check failed: version 0x{found:02x} is not supported by this build. Refusing to guess at forward compatibility."
            ),
            DecayError::UnsupportedFileType { found } => write!(
                f,
                "format: file_type check failed: 0x{found:02x} is neither image (0x01) nor text (0x02)."
            ),
            DecayError::MismatchedFileType {
                extension_kind,
                header_kind,
            } => write!(
                f,
                "open: type check failed: the filename extension indicates {extension_kind} but the header says {header_kind}. Refusing to guess which is correct."
            ),
            DecayError::ReadOnly { path } => write!(
                f,
                "open: writability check failed: '{path}' is read-only. Corruption cannot be written, so the file will not be displayed."
            ),
            DecayError::PayloadTooSmall { found, needed } => write!(
                f,
                "format: header read failed: buffer is {found} bytes but the header needs {needed} bytes."
            ),
            DecayError::InvalidUtf8 => write!(
                f,
                "encode: text read failed: source is not valid UTF-8."
            ),
            DecayError::FilenameNoX { filename } => write!(
                f,
                "open: filename parse failed: '{filename}' contains no positive instability value x in its extension."
            ),
            DecayError::XNotPositive { value } => write!(
                f,
                "open: instability check failed: x = {value} is not a positive number."
            ),
            DecayError::XOutOfRange { value } => write!(
                f,
                "open: filename parse failed: instability value x = '{value}' is too large; the maximum is {}.",
                u32::MAX
            ),
            DecayError::Io { context, source } => write!(f, "{context}: {source}"),
            DecayError::ImageDecode { context } => write!(f, "{context}"),
            DecayError::UnrecognizedExtension { extension } => write!(
                f,
                "encode: output extension '{extension}' is neither an image (idcy) nor a text (tdcy) decayfmt extension."
            ),
            DecayError::PayloadSizeMismatch { expected, found } => write!(
                f,
                "open: image payload check failed: header expects {expected} bytes of pixels but the payload is {found} bytes. The file is truncated or inconsistent."
            ),
            DecayError::ImageEncode { context } => write!(f, "{context}"),
            DecayError::InvalidHeaderV2 { reason } => write!(
                f,
                "format: invalid v2 header: {reason}"
            ),
            DecayError::Crypto { context } => write!(f, "crypto: {context}"),
            DecayError::Tpm { context } => write!(f, "tpm: {context}"),
            DecayError::NvCounter { context } => write!(f, "tpm nv counter: {context}"),
            DecayError::InvalidArgument { context } => write!(f, "invalid argument: {context}"),
        }
    }
}

impl std::error::Error for DecayError {
    /// Exposes the underlying operating system error for the Io variant so callers
    /// can inspect the cause chain. Other variants have no further source.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecayError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
