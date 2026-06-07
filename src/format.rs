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

/// Number of reserved bytes after file_type. Zero-filled on write, ignored on read.
const RESERVED_LEN: usize = 10;

/// Total size of the fixed header: 4 (magic) + 1 (version) + 1 (file_type) + 10 (reserved).
pub const HEADER_SIZE: usize = 4 + 1 + 1 + RESERVED_LEN;

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

/// The parsed, validated header of a decayfmt file. The only meaningful field is
/// the file type; magic and version are validated on read and are not stored as
/// variable state because they are fixed for a given build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub file_type: FileType,
}

impl Header {
    /// Builds a header for a new file of the given type. Used at encode time.
    pub fn new(file_type: FileType) -> Header {
        Header { file_type }
    }

    /// Serializes the header to its fixed 16-byte on-disk form.
    ///
    /// Upholds the invariant that reserved bytes are always zero on write, so the
    /// reserved region carries no hidden state. The header produced here is the
    /// header for the life of the file; it is written once and never rewritten.
    pub fn write(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = VERSION;
        bytes[5] = self.file_type.to_byte();
        // bytes[6..16] are the reserved region. They are already zero from the
        // initializer above and are deliberately left untouched.
        bytes
    }

    /// Parses and validates a header from the start of a buffer.
    ///
    /// Upholds the invariant that a header is only accepted if its magic and
    /// version match this build exactly. The reserved bytes are ignored entirely.
    /// Returns a typed error for every way the buffer can fail to be a header this
    /// build understands; it never partially accepts or guesses.
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

        // Reserved bytes buffer[6..16] are intentionally ignored.
        Ok(Header { file_type })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a valid 16-byte image header buffer for tests to mutate.
    fn valid_image_header() -> Vec<u8> {
        Header::new(FileType::Image).write().to_vec()
    }

    #[test]
    fn correct_header_round_trips_without_mutation() {
        for file_type in [FileType::Image, FileType::Text] {
            let original = Header::new(file_type);
            let bytes = original.write();
            let parsed = Header::read(&bytes).expect("valid header must parse");
            assert_eq!(parsed, original, "round-trip changed the header");
        }
    }

    #[test]
    fn reserved_bytes_are_zero_on_write() {
        let bytes = Header::new(FileType::Text).write();
        assert!(
            bytes[6..HEADER_SIZE].iter().all(|&b| b == 0),
            "reserved region must be zero-filled on write"
        );
    }

    #[test]
    fn magic_and_version_bytes_are_exact() {
        let bytes = Header::new(FileType::Image).write();
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
        // A header with non-zero reserved bytes must still parse: reserved is
        // ignored on read so future versions can use it without breaking us.
        let mut bytes = valid_image_header();
        for b in bytes.iter_mut().take(HEADER_SIZE).skip(6) {
            *b = 0xFF;
        }
        let parsed = Header::read(&bytes).expect("reserved bytes must be ignored");
        assert_eq!(parsed.file_type, FileType::Image);
    }
}
