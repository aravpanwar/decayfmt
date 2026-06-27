//! The decayfmt binary header: definition, serialization, deserialization, and
//! validation of magic bytes and version.
//!
//! This module knows nothing about corruption, file I/O, or the CLI. It turns a
//! fixed 16-byte header into a typed [`Header`] and back. The header is written
//! exactly once at encode time and is never mutated afterward; only the payload
//! that follows it ever changes. The invariant this module upholds is that a
//! buffer is only ever accepted as a decayfmt header if its magic and version are
//! ones this build recognizes. Anything else is a typed refusal, never a guess.

use crate::error::DecayError;

/// The four magic bytes that identify a decayfmt file: ASCII "DCYF".
pub const MAGIC: [u8; 4] = *b"DCYF";

/// The format version this build reads and writes. An unknown version is refused,
/// never interpreted, because the meaning of later versions is not knowable here.
pub const VERSION: u8 = 0x01;

/// file_type byte for an image payload (raw RGBA pixels).
pub const FILE_TYPE_IMAGE: u8 = 0x01;

/// file_type byte for a text payload (raw UTF-8 bytes).
pub const FILE_TYPE_TEXT: u8 = 0x02;

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
            bytes[WIDTH_OFFSET..WIDTH_OFFSET + 4]
                .copy_from_slice(&dimensions.width.to_le_bytes());
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
            other => panic!("expected WrongMagic, got {:?}", other),
        }
    }

    #[test]
    fn wrong_version_is_refused() {
        let mut bytes = valid_image_header();
        bytes[4] = 0x02;
        match Header::read(&bytes) {
            Err(DecayError::UnsupportedVersion { found }) => assert_eq!(found, 0x02),
            other => panic!("expected UnsupportedVersion, got {:?}", other),
        }
    }

    #[test]
    fn unknown_file_type_is_refused() {
        let mut bytes = valid_image_header();
        bytes[5] = 0x09;
        match Header::read(&bytes) {
            Err(DecayError::UnsupportedFileType { found }) => assert_eq!(found, 0x09),
            other => panic!("expected UnsupportedFileType, got {:?}", other),
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
            other => panic!("expected PayloadTooSmall, got {:?}", other),
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
}
