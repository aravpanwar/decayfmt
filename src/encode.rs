//! Encode a source file into a decayfmt file.
//!
//! This module reads a source image or text file and produces either a v1 decayfmt
//! file (a fixed header followed by the raw, uncorrupted payload) or a v2 file (a
//! TPM-sealed header followed by an AES-256-GCM encrypted payload). The v1 path is
//! chosen by a `.idcy<x>`/`.tdcy<x>` name; the v2 path is chosen by a bare
//! `.idcy`/`.tdcy` name and is bound to a TPM. In both cases encoding never corrupts:
//! a freshly encoded file is clean, and corruption only ever happens at open time in
//! open.rs. All file I/O for the encode flow lives here.

use crate::crypto::{encrypt_payload, generate_content_key, generate_payload_nonce};
use crate::error::DecayError;
use crate::format::{FileType, Header, HeaderV2};
use crate::tpm::{Tpm, TpmContext};
use std::fs;
use std::path::{Path, PathBuf};

/// Decodes a source image's bytes into its pixel dimensions and a raw RGBA payload.
///
/// The image crate accepts any format it supports (PNG, JPEG, and others) and is
/// reduced here to raw RGBA, four bytes per pixel, which is exactly what the
/// decayfmt payload stores. The dimensions are returned alongside so the header can
/// record them; the payload is the pixel data only and does not encode its own size.
fn decode_image(source_bytes: &[u8], input: &Path) -> Result<(u32, u32, Vec<u8>), DecayError> {
    let decoded =
        image::load_from_memory(source_bytes).map_err(|error| DecayError::ImageDecode {
            context: format!("encode: decode image '{}': {}", input.display(), error),
        })?;
    let rgba = decoded.to_rgba8();
    let (width, height) = rgba.dimensions();
    Ok((width, height, rgba.into_raw()))
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

/// Encodes a source file at `input` into a decayfmt file at `output`.
///
/// The payload type and the instability value x both come from the output filename
/// (`name.idcy<x>` or `name.tdcy<x>`), parsed by the same routine open uses, so an
/// output name that could never be opened, a missing or malformed x, is refused here
/// rather than producing a permanently unopenable file. The source is read and turned
/// into a raw payload (RGBA for images, UTF-8 for text), and the header plus payload
/// are written out. No corruption is applied; the produced file is clean and parses
/// cleanly via format.rs. The value of x is not stored; it lives only in the filename.
pub fn encode_file(input: &Path, output: &Path) -> Result<(), DecayError> {
    let (file_type, _x) = crate::format::parse_filename(output)?;

    let source_bytes = fs::read(input).map_err(|error| DecayError::Io {
        context: format!("encode: read input '{}'", input.display()),
        source: error,
    })?;

    let (header, payload) = match file_type {
        FileType::Image => {
            let (width, height, payload) = decode_image(&source_bytes, input)?;
            (Header::for_image(width, height), payload)
        }
        FileType::Text => (Header::for_text(), text_payload(source_bytes)?),
    };

    write_decayfmt(output, header, &payload)
}

/// How an output filename selects the encoding version and payload type.
///
/// A v2 output name ends in a bare `.idcy` (image) or `.tdcy` (text) extension with no
/// trailing decay value. A v1 output name keeps the existing `.idcy<x>` / `.tdcy<x>`
/// convention, which carries a positive integer instability value. The name alone therefore
/// determines the payload type and whether the target is the v1 or the v2 (TPM-bound) form;
/// an existing v1 file is never silently reinterpreted as v2 and vice versa.
///
/// The `file_type` and `x` payload of [`EncodeKind::V1`] are carried only for classification;
/// the v1 writer re-derives them from the filename. They are intentionally not read here.
#[allow(dead_code)]
enum EncodeKind {
    V1 { file_type: FileType, x: f64 },
    V2 { file_type: FileType },
}

/// Classifies an output path as a v1 or v2 encode target.
///
/// Bare `.idcy` / `.tdcy` extensions select v2. Anything else is handed to the existing v1
/// [`parse_filename`](crate::format::parse_filename), so a name that v1 could never open (a
/// missing, zero, or non-numeric x) is refused here rather than producing a permanently
/// unopenable file.
fn classify_output(path: &Path) -> Result<EncodeKind, DecayError> {
    let extension = path.extension().and_then(|raw| raw.to_str()).unwrap_or("");
    match extension {
        "idcy" => {
            return Ok(EncodeKind::V2 {
                file_type: FileType::Image,
            })
        }
        "tdcy" => {
            return Ok(EncodeKind::V2 {
                file_type: FileType::Text,
            })
        }
        _ => {}
    }
    let (file_type, x) = crate::format::parse_filename(path)?;
    Ok(EncodeKind::V1 { file_type, x })
}

/// Encodes a source file, routing to v1 or v2.
///
/// This is the entry point the CLI calls. The v2, TPM-bound, encrypted encode is **opt-in**:
/// it runs only when `v2` is `true` and the output name ends in a bare `.idcy` / `.tdcy`
/// (no decay suffix). Without `v2` the default v1 encode runs unchanged on a `.idcy<x>` /
/// `.tdcy<x>` name and is left byte-for-byte identical to before. A bare v2 output name
/// without `-v2` is rejected rather than silently falling back or ignoring the option. When
/// `tcti` is `Some`, a v2 encode connects to that TCTI (e.g. `swtpm:host=127.0.0.1,port=2321`)
/// instead of the platform's default backend (Windows TBS); it is ignored for v1 names, which
/// never touch the TPM.
pub fn encode(input: &Path, output: &Path, v2: bool, tcti: Option<&str>) -> Result<(), DecayError> {
    match classify_output(output)? {
        EncodeKind::V2 { .. } => {
            if !v2 {
                return Err(DecayError::InvalidArgument {
                    context: "v2 output names (ending in a bare .idcy or .tdcy) require -v2"
                        .to_string(),
                });
            }
            let mut tpm = TpmContext::connect_optional(tcti)?;
            encode_v2(input, output, &mut tpm)
        }
        EncodeKind::V1 { .. } => {
            if v2 {
                return Err(DecayError::InvalidArgument {
                    context: "v2 requires an output name ending in a bare .idcy or .tdcy (no decay suffix)"
                        .to_string(),
                });
            }
            encode_file(input, output)
        }
    }
}

/// Encodes a source file at `input` into a v2, TPM-bound file at `output`.
///
/// The v2 sequence is: using the caller-supplied, already-connected TPM, generate a fresh
/// 256-bit content key `K`, seal `K` so it only ever lives in the TPM sealed object and
/// transient memory, allocate a fresh NV counter (recording its actual initial value `c0`),
/// generate a 12-byte payload nonce, build the FINAL [`HeaderV2`] with every field that will
/// be persisted, derive the canonical AAD from that header, encrypt the pristine plaintext
/// exactly once with AES-256-GCM, then write the artifact atomically. The nonce is generated
/// before the header so it is a fixed, authenticated header field. No corruption, no
/// re-encryption, and no counter increment happens at encode time; the counter is only ever
/// advanced at open time.
pub fn encode_v2(input: &Path, output: &Path, tpm: &mut impl Tpm) -> Result<(), DecayError> {
    let file_type = match classify_output(output)? {
        EncodeKind::V2 { file_type } => file_type,
        EncodeKind::V1 { .. } => {
            return Err(DecayError::InvalidArgument {
                context: "v2 encode requires an output name ending in .idcy or .tdcy".to_string(),
            });
        }
    };

    let source_bytes = fs::read(input).map_err(|error| DecayError::Io {
        context: format!("encode: read input '{}'", input.display()),
        source: error,
    })?;

    let (width, height, plaintext) = match file_type {
        FileType::Image => {
            let (width, height, payload) = decode_image(&source_bytes, input)?;
            (width, height, payload)
        }
        FileType::Text => (0, 0, text_payload(source_bytes)?),
    };

    // (a) the TPM is supplied by the caller; (b) generate K, (c) seal K, (d) allocate the
    // NV counter.
    let content_key = generate_content_key();
    let (sealed_pub, sealed_priv) = tpm.seal_content_key(&content_key)?;
    let counter = tpm.allocate_counter()?;

    // (e) a fresh payload nonce, fixed into the final header below.
    let payload_nonce = generate_payload_nonce();
    let payload_nonce_arr: [u8; 12] =
        payload_nonce
            .as_bytes()
            .try_into()
            .map_err(|_| DecayError::Crypto {
                context: "payload nonce is not 12 bytes".to_string(),
            })?;

    // (f) the FINAL header, carrying the sealed blobs and counter identity.
    let header = HeaderV2::new(
        file_type,
        width,
        height,
        counter.nv_index,
        counter.c0,
        payload_nonce_arr,
        sealed_pub,
        sealed_priv,
        counter.nv_auth,
    );

    // (g) serialized header bytes are the AAD, so (h) encrypt only after they exist.
    let aad = header.payload_aad()?;
    let ciphertext = encrypt_payload(&content_key, &plaintext, &payload_nonce, &aad)?;

    let mut header_bytes = Vec::new();
    header.write(&mut header_bytes)?;

    // (i) write header then ciphertext, atomically, only once everything has succeeded.
    write_v2_file_atomically(output, &header_bytes, &ciphertext)
}

/// Writes the header and ciphertext to a temporary path and atomically renames it into place.
/// If the artifact cannot be fully built, no valid-looking v2 file is left behind; the temp
/// file is cleaned up on any failure.
fn write_v2_file_atomically(
    output: &Path,
    header: &[u8],
    ciphertext: &[u8],
) -> Result<(), DecayError> {
    let mut file_bytes = Vec::with_capacity(header.len() + ciphertext.len());
    file_bytes.extend_from_slice(header);
    file_bytes.extend_from_slice(ciphertext);

    let temp_path = temp_path_for(output);
    if let Err(source) = fs::write(&temp_path, &file_bytes) {
        let _ = fs::remove_file(&temp_path);
        return Err(DecayError::Io {
            context: format!("encode: write temporary '{}'", temp_path.display()),
            source,
        });
    }
    fs::rename(&temp_path, output).map_err(|source| {
        let _ = fs::remove_file(&temp_path);
        DecayError::Io {
            context: format!("encode: finalize '{}'", output.display()),
            source,
        }
    })
}

/// Builds a sibling temporary path for the output file, appending `.tmp` so the partial
/// artifact can never be mistaken for a decayfmt file (which requires `.idcy`/`.tdcy`).
fn temp_path_for(output: &Path) -> PathBuf {
    let mut name = output.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{ImageDimensions, FILE_TYPE_TEXT, HEADER_SIZE, MAGIC, VERSION};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Builds a unique path in the system temp directory so concurrent test runs do
    /// not collide. The suffix carries the extension the test needs.
    fn unique_temp_path(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("decayfmt_test_{nanos}_{suffix}"))
    }

    #[test]
    fn encode_text_writes_header_and_exact_payload() {
        let source = b"the quick brown fox jumps over the lazy dog";
        let input = unique_temp_path("source.txt");
        let output = unique_temp_path("note.tdcy3");
        fs::write(&input, source).expect("write test source");

        encode_file(&input, &output).expect("encode text should succeed");

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

        encode_file(&input, &output).expect("encode image should succeed");

        let written = fs::read(&output).expect("read encoded file");
        assert_eq!(&written[0..4], &MAGIC, "magic bytes must be DCYF");
        assert_eq!(written[4], VERSION, "version byte must match");
        let payload_len = written.len() - HEADER_SIZE;
        assert_eq!(
            payload_len,
            (width * height * 4) as usize,
            "image payload must be width * height * 4 bytes"
        );

        let header = Header::read(&written).expect("encoded header must parse");
        assert_eq!(
            header.dimensions,
            Some(ImageDimensions { width, height }),
            "header must record the source image dimensions"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    // The v2 encode is opt-in: without -v2 the default v1 path must be unchanged, and a bare
    // v2 name requires -v2. These are the CLI-facing contract.

    #[test]
    fn v1_encode_is_default_without_v2_flag() {
        let input = unique_temp_path("default_src.txt");
        let output = unique_temp_path("default_note.tdcy5");
        fs::write(&input, b"default v1 payload").expect("write source");

        encode(&input, &output, false, None).expect("default encode must be v1");

        let written = fs::read(&output).expect("read encoded file");
        assert_eq!(
            &written[0..4],
            &MAGIC,
            "default must write a v1 (DCYF) file"
        );
        assert_eq!(written[4], VERSION, "version byte must be v1");
        assert_eq!(
            &written[HEADER_SIZE..],
            b"default v1 payload",
            "v1 payload must be stored verbatim"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn bare_v2_name_without_flag_is_rejected() {
        let input = unique_temp_path("bare_src.txt");
        let output = unique_temp_path("bare_note.tdcy");
        fs::write(&input, b"payload").expect("write source");

        let result = encode(&input, &output, false, None);
        assert!(
            matches!(result, Err(DecayError::InvalidArgument { .. })),
            "a bare v2 name without -v2 must be rejected, got {result:?}"
        );

        let _ = fs::remove_file(&input);
    }

    #[test]
    fn v2_flag_requires_bare_v2_name() {
        let input = unique_temp_path("v2src.txt");
        let output = unique_temp_path("v2_note.tdcy5");
        fs::write(&input, b"payload").expect("write source");

        let result = encode(&input, &output, true, None);
        assert!(
            matches!(result, Err(DecayError::InvalidArgument { .. })),
            "-v2 with a v1-style (decay-suffixed) name must be rejected, got {result:?}"
        );

        let _ = fs::remove_file(&input);
    }
}
