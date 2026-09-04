//! The decayfmt format definition: the binary header and the filename convention.
//!
//! This module owns two pieces of format metadata: the fixed 16-byte header (magic,
//! version, file type, and image dimensions) and the filename convention that carries
//! the payload type and the instability value x (`name.idcy<x>` / `name.tdcy<x>`). It
//! knows nothing about corruption, file I/O, or the CLI. The header is written exactly
//! once at encode time and never mutated afterward; only the payload that follows it
//! ever changes. The invariant this module upholds is that a buffer is only accepted
//! as a header, and a name only accepted as a decayfmt name, if they match this build
//! exactly. Anything else is a typed refusal, never a guess.

use crate::error::DecayError;
use std::path::Path;

/// The four magic bytes that identify a decayfmt file: ASCII "DCYF".
pub const MAGIC: [u8; 4] = *b"DCYF";

/// The four magic bytes that identify a v2 decayfmt file: ASCII "DCF2". v2 is the
/// encrypted, TPM-hardware-bound format; its parsing is not implemented yet.
pub const MAGIC_V2: [u8; 4] = *b"DCF2";

/// The format version this build reads and writes. An unknown version is refused,
/// never interpreted, because the meaning of later versions is not knowable here.
pub const VERSION: u8 = 0x01;

/// The v2 format version, kept wider than v1's single byte to allow the header to
/// grow. v2 is the encrypted, TPM-hardware-bound format; it is not parsed yet.
pub const VERSION_V2: u16 = 2;

/// file_type byte for an image payload (raw RGBA pixels).
pub const FILE_TYPE_IMAGE: u8 = 0x01;

/// file_type byte for a text payload (raw UTF-8 bytes).
pub const FILE_TYPE_TEXT: u8 = 0x02;

/// Filename extension prefix that precedes x for an image, for example `idcy3`.
pub const IMAGE_EXTENSION_PREFIX: &str = "idcy";

/// Filename extension prefix that precedes x for text, for example `tdcy7`.
pub const TEXT_EXTENSION_PREFIX: &str = "tdcy";

/// Byte offset of the 4-byte little-endian image width within the header.
const WIDTH_OFFSET: usize = 6;

/// Byte offset of the 4-byte little-endian image height within the header.
const HEIGHT_OFFSET: usize = 10;

/// Byte offset of the reserved region within the header.
const RESERVED_OFFSET: usize = 14;

/// Number of reserved bytes after the dimensions. Zero-filled on write, ignored on read.
const RESERVED_LEN: usize = 2;

/// Total size of the fixed header: 4 (magic) + 1 (version) + 1 (file_type)
/// + 4 (width) + 4 (height) + 2 (reserved).
pub const HEADER_SIZE: usize = RESERVED_OFFSET + RESERVED_LEN;

/// Size of the fixed portion of a v2 header, before the two variable-length
/// sealed-object fields: 4 (magic) + 2 (version) + 1 (file_type) + 4 (width)
/// + 4 (height) + 4 (nv_index) + 8 (c0) + 4 (n_max) + 12 (payload_nonce).
pub const HEADER_V2_FIXED_LEN: usize = 4 + 2 + 1 + 4 + 4 + 4 + 8 + 4 + 12;

/// Which kind of payload follows the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Image,
    Text,
}

impl FileType {
    /// Maps a FileType to its on-disk byte.
    fn to_byte(self) -> u8 {
        match self {
            FileType::Image => FILE_TYPE_IMAGE,
            FileType::Text => FILE_TYPE_TEXT,
        }
    }

    /// Maps an on-disk byte to a FileType, refusing any byte that is not a known
    /// file type rather than defaulting to one.
    fn from_byte(byte: u8) -> Result<FileType, DecayError> {
        match byte {
            FILE_TYPE_IMAGE => Ok(FileType::Image),
            FILE_TYPE_TEXT => Ok(FileType::Text),
            other => Err(DecayError::UnsupportedFileType { found: other }),
        }
    }

    /// A short human-readable name for this file type, used in error messages when
    /// the filename's extension and the header disagree about the payload type.
    pub fn label(self) -> &'static str {
        match self {
            FileType::Image => "image",
            FileType::Text => "text",
        }
    }
}

/// The v2 header: the encrypted, TPM-hardware-bound format. A v2 file is always bound
/// to a TPM at encode time; there is no passphrase or portable key. It carries the
/// payload type, dimensions, the TPM NV counter identity, the initial counter value,
/// the maximum number of opens, the single payload nonce, and the serialized public
/// and private portions of the TPM sealed object that holds the content key K.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderV2 {
    pub file_type: FileType,
    pub width: u32,
    pub height: u32,
    pub nv_index: u32,
    pub c0: u64,
    pub n_max: u32,
    pub payload_nonce: [u8; 12],
    pub sealed_pub: Vec<u8>,
    pub sealed_priv: Vec<u8>,
}

impl HeaderV2 {
    /// The maximum allowed size, in bytes, of a sealed-object blob in the v2 header.
    /// Keeping an upper bound means a malformed header cannot force validation to inspect
    /// an unbounded blob.
    const MAX_BLOB_LEN: usize = 1 << 20;

    /// Builds a v2 header for a file that is immediately bound to a TPM. The sealed
    /// public and private parts (the TPM sealed object holding K), the NV counter
    /// identity, the initial counter value, and the payload nonce are all supplied by
    /// the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        file_type: FileType,
        width: u32,
        height: u32,
        nv_index: u32,
        c0: u64,
        n_max: u32,
        payload_nonce: [u8; 12],
        sealed_pub: Vec<u8>,
        sealed_priv: Vec<u8>,
    ) -> Self {
        HeaderV2 {
            file_type,
            width,
            height,
            nv_index,
            c0,
            n_max,
            payload_nonce,
            sealed_pub,
            sealed_priv,
        }
    }

    /// Validates the internal consistency of a v2 header.
    ///
    /// A v2 file is always TPM-bound, so it must carry non-empty sealed public and
    /// private parts and a non-zero `nv_index`; `n_max` must be non-zero; and every
    /// variable-length blob must stay within the maximum blob size. Returns a typed
    /// [`DecayError`] naming the first violated invariant.
    pub fn validate(&self) -> Result<(), DecayError> {
        if self.n_max == 0 {
            return Err(DecayError::InvalidHeaderV2 {
                reason: "n_max must be greater than zero".to_string(),
            });
        }
        if self.nv_index == 0 {
            return Err(DecayError::InvalidHeaderV2 {
                reason: "a bound v2 header requires a non-zero nv_index".to_string(),
            });
        }
        match self.file_type {
            FileType::Image => {
                if self.width == 0 || self.height == 0 {
                    return Err(DecayError::InvalidHeaderV2 {
                        reason: "an image header requires non-zero width and height".to_string(),
                    });
                }
            }
            FileType::Text => {
                if self.width != 0 || self.height != 0 {
                    return Err(DecayError::InvalidHeaderV2 {
                        reason: "a text header must have zero width and height".to_string(),
                    });
                }
            }
        }
        if self.sealed_pub.is_empty() || self.sealed_priv.is_empty() {
            return Err(DecayError::InvalidHeaderV2 {
                reason: "bound header requires non-empty sealed public and private parts"
                    .to_string(),
            });
        }

        for blob in [&self.sealed_pub, &self.sealed_priv] {
            if blob.len() > Self::MAX_BLOB_LEN {
                return Err(DecayError::InvalidHeaderV2 {
                    reason: format!(
                        "variable-length blob ({} bytes) exceeds the maximum of {} bytes",
                        blob.len(),
                        Self::MAX_BLOB_LEN
                    ),
                });
            }
        }

        Ok(())
    }

    /// Serializes this v2 header to its explicit binary on-disk form, appending the
    /// bytes to `out`. Fixed fields first, then the two length-prefixed sealed-object
    /// fields. Validation runs first, so an invalid header is never serialized.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<(), DecayError> {
        self.validate()?;

        out.extend_from_slice(&MAGIC_V2);
        out.extend_from_slice(&VERSION_V2.to_le_bytes());
        out.push(self.file_type.to_byte());
        out.extend_from_slice(&self.width.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.nv_index.to_le_bytes());
        out.extend_from_slice(&self.c0.to_le_bytes());
        out.extend_from_slice(&self.n_max.to_le_bytes());
        out.extend_from_slice(&self.payload_nonce);

        write_blob(out, Some(self.sealed_pub.as_slice()));
        write_blob(out, Some(self.sealed_priv.as_slice()));

        Ok(())
    }

    /// Parses a v2 header from the start of `bytes`, returning the header and the number
    /// of bytes consumed so the caller can locate the encrypted payload that follows.
    /// Verifies the magic and version, rejects unknown file types, bounds checks every
    /// length and offset, and re-runs validation before returning. No I/O.
    pub fn read(bytes: &[u8]) -> Result<(Self, usize), DecayError> {
        let mut pos = 0usize;

        let magic = take::<4>(bytes, &mut pos)?;
        if magic != MAGIC_V2 {
            return Err(DecayError::WrongMagic { found: magic });
        }

        let version = u16::from_le_bytes(take::<2>(bytes, &mut pos)?);
        if version != VERSION_V2 {
            return Err(DecayError::UnsupportedVersion {
                found: version as u8,
            });
        }

        let file_type = FileType::from_byte(take::<1>(bytes, &mut pos)?[0])?;
        let width = u32::from_le_bytes(take::<4>(bytes, &mut pos)?);
        let height = u32::from_le_bytes(take::<4>(bytes, &mut pos)?);

        let nv_index = u32::from_le_bytes(take::<4>(bytes, &mut pos)?);
        let c0 = u64::from_le_bytes(take::<8>(bytes, &mut pos)?);
        let n_max = u32::from_le_bytes(take::<4>(bytes, &mut pos)?);

        let payload_nonce = take::<12>(bytes, &mut pos)?;

        let sealed_pub = read_blob(bytes, &mut pos)?;
        let sealed_priv = read_blob(bytes, &mut pos)?;

        let header = HeaderV2 {
            file_type,
            width,
            height,
            nv_index,
            c0,
            n_max,
            payload_nonce,
            sealed_pub,
            sealed_priv,
        };

        header.validate()?;

        Ok((header, pos))
    }

    /// Builds the canonical bytes authenticated as the payload AAD.
    ///
    /// This is exactly the canonical serialized v2 header bytes produced by
    /// [`HeaderV2::write`], so the payload is bound to every header field: magic,
    /// version, file type, dimensions, `nv_index`, `c0`, `n_max`, the payload nonce, and
    /// the TPM sealed object. It deliberately excludes the payload/ciphertext. Callers
    /// pass these exact bytes as the AAD to both the payload encrypt and decrypt
    /// primitives so the two operations authenticate the same bytes.
    pub fn payload_aad(&self) -> Result<Vec<u8>, DecayError> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }
}

/// Appends one length-prefixed variable-length field: a u32 little-endian length,
/// then that many bytes. `None` is written as length 0 with no payload bytes.
fn write_blob(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    let len = bytes.map_or(0, |data| data.len() as u32);
    out.extend_from_slice(&len.to_le_bytes());
    if let Some(data) = bytes {
        out.extend_from_slice(data);
    }
}

/// Reads `N` bytes at the cursor `*pos`, advancing it, and rejects a short buffer or an
/// offset that would overflow.
fn take<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], DecayError> {
    let end = (*pos).checked_add(N).ok_or(DecayError::InvalidHeaderV2 {
        reason: "v2 header offset overflow".to_string(),
    })?;
    if end > bytes.len() {
        return Err(DecayError::InvalidHeaderV2 {
            reason: format!(
                "truncated v2 header: need {} bytes at offset {}, but the buffer has {} bytes",
                N,
                *pos,
                bytes.len()
            ),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Ok(out)
}

/// Reads one length-prefixed variable-length field, rejecting a length above the maximum
/// blob size and a length that extends past the buffer.
fn read_blob(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, DecayError> {
    let len = u32::from_le_bytes(take::<4>(bytes, pos)?) as usize;
    if len > HeaderV2::MAX_BLOB_LEN {
        return Err(DecayError::InvalidHeaderV2 {
            reason: format!(
                "variable-length blob length {} exceeds the maximum of {} bytes",
                len,
                HeaderV2::MAX_BLOB_LEN
            ),
        });
    }
    let end = (*pos).checked_add(len).ok_or(DecayError::InvalidHeaderV2 {
        reason: "v2 header offset overflow".to_string(),
    })?;
    if end > bytes.len() {
        return Err(DecayError::InvalidHeaderV2 {
            reason: format!(
                "truncated v2 header: blob of {} bytes at offset {} extends past the buffer of {} bytes",
                len,
                *pos,
                bytes.len()
            ),
        });
    }
    let data = bytes[*pos..end].to_vec();
    *pos = end;
    Ok(data)
}

/// Parses the decayfmt filename convention into the payload type and instability x.
///
/// The convention is `name.idcy<x>` for images and `name.tdcy<x>` for text, where x
/// is a positive integer. The payload type comes from the prefix and x from the
/// integer suffix. Both encode (to validate its output name) and open (to read x and
/// cross-check the type against the header) go through here, so the naming rule lives
/// in exactly one place. Every way a name can fail to fit the convention is a distinct
/// typed error: an unrecognized prefix, a missing or non-numeric x, a zero x, or an x
/// too large to fit a u32. x is never inferred from anywhere but the filename.
pub fn parse_filename(path: &Path) -> Result<(FileType, f64), DecayError> {
    let extension = path.extension().and_then(|raw| raw.to_str()).unwrap_or("");

    let (file_type, digits) = if let Some(rest) = extension.strip_prefix(IMAGE_EXTENSION_PREFIX) {
        (FileType::Image, rest)
    } else if let Some(rest) = extension.strip_prefix(TEXT_EXTENSION_PREFIX) {
        (FileType::Text, rest)
    } else {
        return Err(DecayError::UnrecognizedExtension {
            extension: extension.to_string(),
        });
    };

    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DecayError::FilenameNoX {
            filename: path.to_string_lossy().into_owned(),
        });
    }

    match digits.parse::<u32>() {
        Ok(0) => Err(DecayError::XNotPositive { value: 0.0 }),
        Ok(value) => Ok((file_type, f64::from(value))),
        Err(_) => Err(DecayError::XOutOfRange {
            value: digits.to_string(),
        }),
    }
}

/// The pixel dimensions of an image payload. Stored in the header so the flat RGBA
/// payload can be turned back into a viewable image when the file is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageDimensions {
    pub width: u32,
    pub height: u32,
}

/// The parsed, validated header of a decayfmt file. It carries the payload type and,
/// for images, the pixel dimensions needed to interpret the raw RGBA payload. Magic
/// and version are validated on read and not stored, because they are fixed for a
/// given build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub file_type: FileType,
    /// Present only for images; None for text, which has no dimensions.
    pub dimensions: Option<ImageDimensions>,
}

/// Reads a little-endian u32 from `buffer` at `offset`. The caller must have already
/// checked that the buffer is at least HEADER_SIZE bytes, so the four bytes are in range.
fn read_u32_le(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

impl Header {
    /// Builds a header for an image payload of the given pixel dimensions.
    pub fn for_image(width: u32, height: u32) -> Header {
        Header {
            file_type: FileType::Image,
            dimensions: Some(ImageDimensions { width, height }),
        }
    }

    /// Builds a header for a text payload, which carries no dimensions.
    pub fn for_text() -> Header {
        Header {
            file_type: FileType::Text,
            dimensions: None,
        }
    }

    /// Serializes the header to its fixed 16-byte on-disk form.
    ///
    /// Upholds the invariant that the reserved bytes are always zero on write. Image
    /// dimensions are written as two little-endian u32 values; for text those bytes
    /// stay zero. The header produced here is written once and never rewritten.
    pub fn write(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = VERSION;
        bytes[5] = self.file_type.to_byte();
        if let Some(dimensions) = self.dimensions {
            bytes[WIDTH_OFFSET..WIDTH_OFFSET + 4].copy_from_slice(&dimensions.width.to_le_bytes());
            bytes[HEIGHT_OFFSET..HEIGHT_OFFSET + 4]
                .copy_from_slice(&dimensions.height.to_le_bytes());
        }
        // For text the dimension bytes stay zero, and the reserved bytes at
        // bytes[RESERVED_OFFSET..] are always left zero.
        bytes
    }

    /// Parses and validates a header from the start of a buffer.
    ///
    /// Upholds the invariant that a header is only accepted if its magic and version
    /// match this build exactly. Image dimensions are read from the header; for text
    /// they are absent. The trailing reserved bytes are ignored. Returns a typed
    /// error for every way the buffer can fail to be a header this build understands.
    pub fn read(buffer: &[u8]) -> Result<Header, DecayError> {
        if buffer.len() < HEADER_SIZE {
            return Err(DecayError::PayloadTooSmall {
                found: buffer.len(),
                needed: HEADER_SIZE,
            });
        }

        let mut found_magic = [0u8; 4];
        found_magic.copy_from_slice(&buffer[0..4]);
        if found_magic != MAGIC {
            return Err(DecayError::WrongMagic { found: found_magic });
        }

        let version = buffer[4];
        if version != VERSION {
            return Err(DecayError::UnsupportedVersion { found: version });
        }

        let file_type = FileType::from_byte(buffer[5])?;
        let dimensions = match file_type {
            FileType::Image => Some(ImageDimensions {
                width: read_u32_le(buffer, WIDTH_OFFSET),
                height: read_u32_le(buffer, HEIGHT_OFFSET),
            }),
            FileType::Text => None,
        };

        // The reserved bytes at buffer[RESERVED_OFFSET..HEADER_SIZE] are ignored.
        Ok(Header {
            file_type,
            dimensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a valid image header buffer with known dimensions for tests to mutate.
    fn valid_image_header() -> Vec<u8> {
        Header::for_image(640, 480).write().to_vec()
    }

    #[test]
    fn image_header_round_trips_with_dimensions() {
        let original = Header::for_image(640, 480);
        let bytes = original.write();
        let parsed = Header::read(&bytes).expect("valid image header must parse");
        assert_eq!(parsed, original, "image round-trip changed the header");
        assert_eq!(
            parsed.dimensions,
            Some(ImageDimensions {
                width: 640,
                height: 480
            })
        );
    }

    #[test]
    fn text_header_round_trips_without_dimensions() {
        let original = Header::for_text();
        let bytes = original.write();
        let parsed = Header::read(&bytes).expect("valid text header must parse");
        assert_eq!(parsed, original, "text round-trip changed the header");
        assert_eq!(parsed.dimensions, None, "text headers carry no dimensions");
    }

    #[test]
    fn dimensions_are_written_little_endian() {
        let bytes = Header::for_image(0x0403_0201, 0x0807_0605).write();
        assert_eq!(
            &bytes[6..10],
            &[0x01, 0x02, 0x03, 0x04],
            "width must be little-endian"
        );
        assert_eq!(
            &bytes[10..14],
            &[0x05, 0x06, 0x07, 0x08],
            "height must be little-endian"
        );
    }

    #[test]
    fn reserved_bytes_are_zero_on_write() {
        // Even with dimensions set, the trailing reserved bytes must stay zero.
        let bytes = Header::for_image(640, 480).write();
        assert!(
            bytes[14..HEADER_SIZE].iter().all(|&b| b == 0),
            "reserved region must be zero-filled on write"
        );
    }

    #[test]
    fn magic_and_version_bytes_are_exact() {
        let bytes = Header::for_image(2, 2).write();
        assert_eq!(&bytes[0..4], b"DCYF", "magic bytes must be DCYF");
        assert_eq!(bytes[4], 0x01, "version byte must be 0x01");
        assert_eq!(bytes[5], FILE_TYPE_IMAGE, "file_type byte must be image");
    }

    #[test]
    fn wrong_magic_is_refused() {
        let mut bytes = valid_image_header();
        bytes[0] = b'X';
        match Header::read(&bytes) {
            Err(DecayError::WrongMagic { found }) => assert_eq!(found[0], b'X'),
            other => panic!("expected WrongMagic, got {other:?}"),
        }
    }

    #[test]
    fn wrong_version_is_refused() {
        let mut bytes = valid_image_header();
        bytes[4] = 0x02;
        match Header::read(&bytes) {
            Err(DecayError::UnsupportedVersion { found }) => assert_eq!(found, 0x02),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn unknown_file_type_is_refused() {
        let mut bytes = valid_image_header();
        bytes[5] = 0x09;
        match Header::read(&bytes) {
            Err(DecayError::UnsupportedFileType { found }) => assert_eq!(found, 0x09),
            other => panic!("expected UnsupportedFileType, got {other:?}"),
        }
    }

    #[test]
    fn buffer_smaller_than_header_is_refused() {
        let short = [0u8; HEADER_SIZE - 1];
        match Header::read(&short) {
            Err(DecayError::PayloadTooSmall { found, needed }) => {
                assert_eq!(found, HEADER_SIZE - 1);
                assert_eq!(needed, HEADER_SIZE);
            }
            other => panic!("expected PayloadTooSmall, got {other:?}"),
        }
    }

    #[test]
    fn reserved_bytes_are_ignored_on_read() {
        // Only the trailing reserved bytes are ignored; flipping them must not stop
        // the header from parsing nor disturb the dimensions read before them.
        let mut bytes = valid_image_header();
        for b in bytes.iter_mut().take(HEADER_SIZE).skip(RESERVED_OFFSET) {
            *b = 0xFF;
        }
        let parsed = Header::read(&bytes).expect("reserved bytes must be ignored");
        assert_eq!(parsed.file_type, FileType::Image);
        assert_eq!(
            parsed.dimensions,
            Some(ImageDimensions {
                width: 640,
                height: 480
            })
        );
    }

    #[test]
    fn parse_filename_reads_type_and_x() {
        assert_eq!(
            parse_filename(Path::new("photo.idcy3")).expect("idcy3 parses"),
            (FileType::Image, 3.0)
        );
        assert_eq!(
            parse_filename(Path::new("note.tdcy12")).expect("tdcy12 parses"),
            (FileType::Text, 12.0)
        );
    }

    #[test]
    fn parse_filename_refuses_unrecognized_extension() {
        for name in ["photo.png", "note.txt", "no_extension"] {
            assert!(
                matches!(
                    parse_filename(Path::new(name)),
                    Err(DecayError::UnrecognizedExtension { .. })
                ),
                "'{name}' should be an unrecognized extension",
            );
        }
    }

    #[test]
    fn parse_filename_refuses_missing_or_non_numeric_x() {
        for name in ["photo.idcy", "note.tdcyx", "photo.idcy3a"] {
            assert!(
                matches!(
                    parse_filename(Path::new(name)),
                    Err(DecayError::FilenameNoX { .. })
                ),
                "'{name}' should yield FilenameNoX",
            );
        }
    }

    #[test]
    fn parse_filename_refuses_zero_x() {
        assert!(matches!(
            parse_filename(Path::new("photo.idcy0")),
            Err(DecayError::XNotPositive { .. })
        ));
    }

    #[test]
    fn parse_filename_refuses_x_too_large_for_u32() {
        // A run of digits that overflows u32 reports an out-of-range error, not the
        // misleading "no x" error, since there clearly is an x, it is just too big.
        assert!(matches!(
            parse_filename(Path::new("photo.idcy99999999999")),
            Err(DecayError::XOutOfRange { .. })
        ));
    }

    /// A small, valid payload nonce used in HeaderV2 tests.
    const TEST_NONCE: [u8; 12] = [0xCD; 12];

    /// Returns a minimal valid v2 (TPM-bound) header for HeaderV2 tests.
    fn valid_header() -> HeaderV2 {
        HeaderV2::new(
            FileType::Image,
            2,
            2,
            7,
            12345,
            10,
            TEST_NONCE,
            vec![4, 5, 6],
            vec![7, 8, 9],
        )
    }

    #[test]
    fn v2_constructor_sets_expected_fields() {
        let header = valid_header();
        assert_eq!(header.file_type, FileType::Image);
        assert_eq!(header.width, 2);
        assert_eq!(header.height, 2);
        assert_eq!(header.nv_index, 7);
        assert_eq!(header.c0, 12345);
        assert_eq!(header.n_max, 10);
        assert_eq!(header.payload_nonce, TEST_NONCE);
        assert_eq!(header.sealed_pub, vec![4, 5, 6]);
        assert_eq!(header.sealed_priv, vec![7, 8, 9]);
    }

    #[test]
    fn valid_v2_header_passes_validation() {
        valid_header()
            .validate()
            .expect("a valid v2 header must validate");
    }

    #[test]
    fn n_max_zero_is_rejected() {
        let header = HeaderV2::new(
            FileType::Text,
            0,
            0,
            7,
            12345,
            0,
            TEST_NONCE,
            vec![4],
            vec![5],
        );
        assert!(matches!(
            header.validate(),
            Err(DecayError::InvalidHeaderV2 { .. })
        ));
    }

    #[test]
    fn zero_nv_index_is_rejected() {
        let header = HeaderV2::new(
            FileType::Text,
            0,
            0,
            0,
            12345,
            10,
            TEST_NONCE,
            vec![4],
            vec![5],
        );
        assert!(matches!(
            header.validate(),
            Err(DecayError::InvalidHeaderV2 { .. })
        ));
    }

    #[test]
    fn empty_sealed_pub_is_rejected() {
        let header = HeaderV2::new(
            FileType::Text,
            0,
            0,
            7,
            12345,
            10,
            TEST_NONCE,
            Vec::new(),
            vec![5],
        );
        assert!(matches!(
            header.validate(),
            Err(DecayError::InvalidHeaderV2 { .. })
        ));
    }

    #[test]
    fn empty_sealed_priv_is_rejected() {
        let header = HeaderV2::new(
            FileType::Text,
            0,
            0,
            7,
            12345,
            10,
            TEST_NONCE,
            vec![4],
            Vec::new(),
        );
        assert!(matches!(
            header.validate(),
            Err(DecayError::InvalidHeaderV2 { .. })
        ));
    }

    #[test]
    fn oversized_blob_is_rejected() {
        let header = HeaderV2::new(
            FileType::Text,
            0,
            0,
            7,
            12345,
            10,
            TEST_NONCE,
            vec![0u8; HeaderV2::MAX_BLOB_LEN + 1],
            vec![5],
        );
        assert!(matches!(
            header.validate(),
            Err(DecayError::InvalidHeaderV2 { .. })
        ));
    }

    #[test]
    fn v2_round_trip() {
        let header = valid_header();
        let mut bytes = Vec::new();
        header.write(&mut bytes).expect("header must serialize");

        let (parsed, consumed) = HeaderV2::read(&bytes).expect("header must parse");
        assert_eq!(parsed, header);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn v2_deterministic_serialization() {
        let header = valid_header();
        let mut first = Vec::new();
        let mut second = Vec::new();
        header.write(&mut first).expect("first write");
        header.write(&mut second).expect("second write");
        assert_eq!(first, second, "serialization must be deterministic");
    }

    #[test]
    fn v2_magic_and_version_bytes_are_exact() {
        let mut bytes = Vec::new();
        valid_header().write(&mut bytes).expect("write header");
        assert_eq!(&bytes[0..4], &MAGIC_V2[..], "magic bytes must be DCF2");
        assert_eq!(
            &bytes[4..6],
            &VERSION_V2.to_le_bytes()[..],
            "version must be 2 little-endian"
        );
    }

    #[test]
    fn v2_truncated_fixed_header_is_rejected() {
        let mut bytes = Vec::new();
        valid_header().write(&mut bytes).expect("write header");
        let short = &bytes[..HEADER_V2_FIXED_LEN - 1];
        assert!(matches!(
            HeaderV2::read(short),
            Err(DecayError::InvalidHeaderV2 { .. })
        ));
    }

    #[test]
    fn v2_truncated_variable_field_is_rejected() {
        let mut bytes = Vec::new();
        valid_header().write(&mut bytes).expect("write header");
        // Trim two bytes off the trailing sealed_priv content; its length field still
        // claims three bytes, so read_blob must report a truncated buffer.
        let short = &bytes[..bytes.len() - 2];
        assert!(matches!(
            HeaderV2::read(short),
            Err(DecayError::InvalidHeaderV2 { .. })
        ));
    }

    #[test]
    fn v2_oversized_variable_field_is_rejected() {
        let mut bytes = Vec::new();
        valid_header().write(&mut bytes).expect("write header");
        // The first sealed-object length field sits at the end of the fixed region.
        let oversized = (HeaderV2::MAX_BLOB_LEN as u32) + 1;
        bytes[HEADER_V2_FIXED_LEN..HEADER_V2_FIXED_LEN + 4]
            .copy_from_slice(&oversized.to_le_bytes());
        assert!(matches!(
            HeaderV2::read(&bytes),
            Err(DecayError::InvalidHeaderV2 { .. })
        ));
    }

    #[test]
    fn v2_invalid_file_type_is_rejected() {
        let mut bytes = Vec::new();
        valid_header().write(&mut bytes).expect("write header");
        bytes[6] = 0x09; // file_type byte, offset 6
        assert!(matches!(
            HeaderV2::read(&bytes),
            Err(DecayError::UnsupportedFileType { .. })
        ));
    }

    #[test]
    fn v2_payload_nonce_is_serialized_in_layout_order() {
        let header = valid_header();
        let mut bytes = Vec::new();
        header.write(&mut bytes).expect("write header");

        // payload_nonce is the last fixed field, at offset 31 in a 43-byte fixed region.
        assert_eq!(
            &bytes[31..43],
            &TEST_NONCE[..],
            "payload_nonce at offset 31"
        );

        let (parsed, _) = HeaderV2::read(&bytes).expect("header must parse");
        assert_eq!(parsed.payload_nonce, TEST_NONCE);
    }

    #[test]
    fn payload_aad_equals_write_bytes() {
        let header = valid_header();
        let aad = header.payload_aad().expect("payload AAD");
        let mut written = Vec::new();
        header.write(&mut written).expect("write header");
        assert_eq!(
            aad, written,
            "payload AAD must equal the canonical serialized header bytes"
        );
    }

    #[test]
    fn identical_headers_have_identical_aad() {
        let a = valid_header();
        let b = valid_header();
        assert_eq!(
            a.payload_aad().expect("AAD"),
            b.payload_aad().expect("AAD"),
            "identical headers must produce identical AAD"
        );
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn changing_any_authored_header_field_changes_aad() {
        let base_aad = valid_header().payload_aad().expect("base AAD");

        // Each closure is a non-capturing mutation that coerces to a fn pointer, so the
        // array holds a homogeneous type.
        let cases: [(&str, fn(&mut HeaderV2)); 9] = [
            ("file_type", |h: &mut HeaderV2| {
                h.file_type = FileType::Text;
                h.width = 0;
                h.height = 0;
            }),
            ("width", |h: &mut HeaderV2| h.width += 1),
            ("height", |h: &mut HeaderV2| h.height += 1),
            ("nv_index", |h: &mut HeaderV2| h.nv_index += 1),
            ("c0", |h: &mut HeaderV2| h.c0 += 1),
            ("n_max", |h: &mut HeaderV2| h.n_max += 1),
            ("payload_nonce", |h: &mut HeaderV2| {
                h.payload_nonce[0] ^= 0xFF
            }),
            ("sealed_pub", |h: &mut HeaderV2| h.sealed_pub[0] ^= 0xFF),
            ("sealed_priv", |h: &mut HeaderV2| h.sealed_priv[0] ^= 0xFF),
        ];

        for (name, mutate) in cases {
            let mut header = valid_header();
            mutate(&mut header);
            let aad = header.payload_aad().expect("AAD must remain valid");
            assert_ne!(
                aad, base_aad,
                "changing the {name} field must change the payload AAD"
            );
        }
    }

    #[test]
    fn payload_aad_round_trips_through_crypto() {
        use crate::crypto::{
            decrypt_payload, encrypt_payload, generate_content_key, generate_payload_nonce,
        };

        let header = valid_header();
        let aad = header.payload_aad().expect("payload AAD");
        let key = generate_content_key();
        let nonce = generate_payload_nonce();
        let plaintext: &[u8] = b"the canonical payload bytes";

        let ct = encrypt_payload(&key, plaintext, &nonce, &aad).expect("encrypt payload");
        let pt = decrypt_payload(&key, &ct, &nonce, &aad).expect("decrypt payload");
        assert_eq!(
            pt, plaintext,
            "AAD must round-trip unchanged through the crypto primitives"
        );
    }
}
