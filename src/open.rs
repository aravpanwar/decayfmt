//! Open a decayfmt file, then display it.
//!
//! This module owns the entire open flow and all of its file I/O. The v1 flow is
//! unchanged: x is parsed from the filename, the file is confirmed writable, the
//! payload is corrupted, the corrupted bytes are written back to disk, and only then
//! is the result displayed. Corruption is paid before display, so a crash mid-flow
//! can never hand back a free, uncorrupted read. The v2 flow (a bare `.idcy`/`.tdcy`
//! name) is an encrypted, TPM-bound file: its immutable ciphertext is decrypted,
//! degraded only in memory, and the on-disk artifact is never modified.

use crate::corrupt::corrupt;
use crate::crypto::{decrypt_payload, ContentKey, PayloadNonce};
use crate::error::DecayError;
use crate::format::{parse_filename, FileType, Header, HeaderV2, ImageDimensions, HEADER_SIZE};
use crate::tpm::{Tpm, TpmContext};
use fs2::FileExt;
use std::fs::OpenOptions;
use std::io::{IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// Number of bytes per pixel in an RGBA payload, used to size the display image.
const RGBA_BYTES_PER_PIXEL: usize = 4;

/// Confirms the file can be written before any corruption is attempted.
///
/// The format contract is that opening costs a corruption. If the file is
/// read-only that corruption cannot be written, so we fail closed here, before
/// reading or displaying anything, rather than discovering it after a display.
fn ensure_writable(path: &Path) -> Result<(), DecayError> {
    let metadata = std::fs::metadata(path).map_err(|error| DecayError::Io {
        context: format!("open: stat '{}'", path.display()),
        source: error,
    })?;
    if metadata.permissions().readonly() {
        return Err(DecayError::ReadOnly {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

/// Corrupts a decayfmt file in place on disk and returns its header and the new
/// file bytes.
///
/// This is the persisted half of the open flow and the part that upholds the
/// contract: parse x, verify writability, corrupt the payload, write it back. It
/// performs no display, so the corruption it commits never depends on anything
/// being shown. The header is read but never changed; only the payload is corrupted.
fn decay_in_place(path: &Path) -> Result<(Header, Vec<u8>), DecayError> {
    let (filename_type, x) = parse_filename(path)?;
    ensure_writable(path)?;

    let mut file_bytes = std::fs::read(path).map_err(|error| DecayError::Io {
        context: format!("open: read '{}'", path.display()),
        source: error,
    })?;

    let header = Header::read(&file_bytes)?;

    // The extension prefix and the header must agree on the payload type. If they
    // disagree, for example an image file renamed to a .tdcy<x> name, refuse rather
    // than trust one source over the other.
    if filename_type != header.file_type {
        return Err(DecayError::MismatchedFileType {
            extension_kind: filename_type.label(),
            header_kind: header.file_type.label(),
        });
    }

    // Corrupt the payload in place. The header occupies the first HEADER_SIZE bytes
    // and is left untouched; everything after it is the payload.
    corrupt(&mut file_bytes[HEADER_SIZE..], header.file_type, x);

    // Persist the corruption by overwriting only the payload region in place. The
    // header bytes on disk are never rewritten, matching the contract that the header
    // is immutable after encode, and because corruption preserves length the file is
    // never truncated. This is the point of no return: once the write lands the
    // previous payload state is gone. A crash mid-write leaves a partially corrupted
    // payload behind an intact header, so the file still decays rather than bricking.
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| DecayError::Io {
            context: format!("open: reopen for write '{}'", path.display()),
            source: error,
        })?;
    file.seek(SeekFrom::Start(HEADER_SIZE as u64))
        .map_err(|error| DecayError::Io {
            context: format!("open: seek past header in '{}'", path.display()),
            source: error,
        })?;
    file.write_all(&file_bytes[HEADER_SIZE..])
        .map_err(|error| DecayError::Io {
            context: format!("open: write corrupted payload to '{}'", path.display()),
            source: error,
        })?;

    Ok((header, file_bytes))
}

/// Opens a decayfmt file. v1 files corrupt in place then display; v2 files consume one
/// TPM open, decrypt, and degrade only in memory.
///
/// A bare `.idcy`/`.tdcy` name selects the v2 (TPM-bound) path. Everything else is the
/// unchanged v1 flow, in which the file is corrupted and persisted first and then
/// displayed. Dimensions are present exactly for images, so their presence selects the
/// display path. When `tcti` is `Some`, a v2 open connects to that TCTI (e.g.
/// `swtpm:host=127.0.0.1,port=2321`) instead of the default `/dev/tpmrm0`; it is ignored for
/// v1 files, which never touch the TPM.
pub fn open_file(path: &Path, tcti: Option<&str>) -> Result<(), DecayError> {
    cleanup_old_view_files();
    // Route on the actual file format, not the filename: a v2 (DCF2) file is opened through
    // the v2 path regardless of its name, and a v1 (DCYF) file through the v1 path. This lets
    // an existing DCF2 .idcy/.tdcy file open through v2 without an opt-in flag, and keeps a
    // v1 file from ever being mistaken for a v2 file on the basis of a bare extension.
    if file_is_v2(path)? {
        let mut tpm = TpmContext::connect_optional(tcti)?;
        return open_v2_file(path, &mut tpm);
    }
    let (header, file_bytes) = decay_in_place(path)?;
    let payload = &file_bytes[HEADER_SIZE..];
    match header.dimensions {
        Some(dimensions) => display_image(payload, dimensions),
        None => display_text(payload),
    }
}

/// True when `path` is a v2 (DCF2) file, detected from its leading magic bytes.
///
/// A decayfmt file is identified by its format, not its filename: v2 files begin with the
/// `DCF2` magic. The file is opened and the first four bytes are read; anything that is not
/// the v2 magic (including a too-short file) is treated as a v1 file so the v1 header check can
/// produce the precise "not a decayfmt file" error.
fn file_is_v2(path: &Path) -> Result<bool, DecayError> {
    let mut file = std::fs::File::open(path).map_err(|error| DecayError::Io {
        context: format!("open: read '{}'", path.display()),
        source: error,
    })?;
    let mut magic = [0u8; 4];
    let read = std::io::Read::read(&mut file, &mut magic).map_err(|error| DecayError::Io {
        context: format!("open: read '{}'", path.display()),
        source: error,
    })?;
    Ok(read == 4 && magic == crate::format::MAGIC_V2)
}

/// Maps the current TPM counter to the 0-based open index, failing closed.
///
/// The index is `counter - c0`, the number of opens already consumed. It is bound to
/// this file because a v2 file owns a freshly allocated per-file counter. A counter
/// that has rolled back below `c0` is a rollback/inconsistent state and is refused;
/// reaching `n_max` opens is refused as exhausted. Neither can be repaired.
fn open_index_for(counter: u64, c0: u64, n_max: u32, nv_index: u32) -> Result<u64, DecayError> {
    if counter < c0 {
        return Err(DecayError::NvCounter {
            context: format!(
                "counter {counter} at index {nv_index:#010x} is less than its initial c0 {c0}"
            ),
        });
    }
    let open_index = counter - c0;
    if open_index >= u64::from(n_max) {
        return Err(DecayError::NvCounter {
            context: format!(
                "already exhausted: open_index {open_index} reaches n_max {n_max} at index {nv_index:#010x}"
            ),
        });
    }
    Ok(open_index)
}

/// Runs the v2 open (parse, counter, decrypt, degrade) and returns the degraded plaintext
/// plus the type/dimensions needed to present it. No display is performed, so tests can
/// drive the real logic without launching a viewer.
///
/// The on-disk artifact is never modified. The counter is advanced before any secret is
/// touched or released, so a failed open still spends the open and the file can never be
/// rolled back to a less-corrupted state. A tampered header or ciphertext fails AES-GCM
/// authentication.
fn open_v2_processing(
    path: &Path,
    tpm: &mut impl Tpm,
) -> Result<(FileType, ImageDimensions, Vec<u8>), DecayError> {
    // Serialize concurrent opens of the same .tdcy so that the read-counter and
    // increment-counter steps are atomic with respect to each other. Without this, two
    // simultaneous opens could both read the same pre-increment counter and therefore
    // derive the same open_index. We lock the .tdcy itself (an advisory lock on the file,
    // not on its contents) exclusively; the kernel releases it when the File is dropped or
    // the process exits, so a crash cannot leave it permanently held.
    let mut file = std::fs::File::open(path).map_err(|error| DecayError::Io {
        context: format!("open: open '{}'", path.display()),
        source: error,
    })?;
    file.lock_exclusive().map_err(|error| DecayError::Io {
        context: format!("open: lock '{}' for a single open", path.display()),
        source: error,
    })?;

    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes)
        .map_err(|error| DecayError::Io {
            context: format!("open: read '{}'", path.display()),
            source: error,
        })?;

    // (1) parse HeaderV2; the DCF2 magic and version are validated inside read().
    let (header, header_len) = HeaderV2::read(&file_bytes)?;
    let ciphertext = &file_bytes[header_len..];

    // The extension must agree with the authenticated header type, mirroring the v1
    // mismatch check: an image file must not carry a text header, and vice versa.
    let expected_type = match path.extension().and_then(|raw| raw.to_str()) {
        Some("idcy") => FileType::Image,
        Some("tdcy") => FileType::Text,
        _ => {
            return Err(DecayError::UnrecognizedExtension {
                extension: path
                    .extension()
                    .and_then(|raw| raw.to_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    };
    if header.file_type != expected_type {
        return Err(DecayError::MismatchedFileType {
            extension_kind: expected_type.label(),
            header_kind: header.file_type.label(),
        });
    }

    // (4) the caller supplies an already-connected TPM.

    // (5) the NV index from the header must exist, be an NvIndexType::Counter, and be
    // exactly 8 bytes. A nonexistent index also fails here.
    tpm.validate_counter(header.nv_index)?;

    // (6) read the current counter, then (7) fail closed on rollback/exhaustion.
    let counter = tpm.read_counter(header.nv_index)?;
    let open_index = open_index_for(counter, header.c0, header.n_max, header.nv_index)?;

    // (9) consume the open by incrementing BEFORE unsealing or decrypting. If this fails,
    // no secret is touched; if it succeeds, the open is spent even if a later step fails.
    tpm.increment_counter(header.nv_index)?;

    // (10)/(11) load the sealed object and unseal K.
    let mut key_bytes = tpm.unseal_content_key(&header.sealed_pub, &header.sealed_priv)?;
    let key = ContentKey::from_bytes(key_bytes);
    key_bytes.zeroize();

    // (12) decrypt the immutable ciphertext with the header bytes as AAD. A tampered
    // header or ciphertext fails AES-GCM authentication.
    let nonce = PayloadNonce::from_bytes(header.payload_nonce);
    let aad = header.payload_aad()?;
    let mut plaintext = decrypt_payload(&key, ciphertext, &nonce, &aad)?;

    // (14) apply the existing degradation in memory using the 0-based open index. The
    // ciphertext on disk is never modified or re-encrypted.
    corrupt(&mut plaintext, header.file_type, open_index as f64);

    Ok((
        header.file_type,
        ImageDimensions {
            width: header.width,
            height: header.height,
        },
        plaintext,
    ))
}

/// Opens a v2, TPM-bound file: authenticate it, consume one open on the TPM, decrypt
/// the immutable ciphertext, degrade in memory, and display.
///
/// The on-disk artifact is never modified. The counter is advanced before any secret is
/// touched or released, so a failed open still spends the open and the file can never be
/// rolled back to a less-corrupted state. A tampered header or ciphertext fails AES-GCM
/// authentication.
fn open_v2_file(path: &Path, tpm: &mut impl Tpm) -> Result<(), DecayError> {
    let (file_type, dimensions, plaintext) = open_v2_processing(path, tpm)?;
    match file_type {
        FileType::Image => display_image(&plaintext, dimensions),
        FileType::Text => display_text(&plaintext),
    }
}

/// Displays a corrupted text payload.
///
/// The payload may no longer be valid UTF-8 after corruption, so it is rendered
/// lossily: invalid byte sequences become the Unicode replacement character rather
/// than causing a failure. Corruption is allowed to break the text; display is not.
///
/// The text is always written to stdout. When stdout is not a terminal, for example
/// when decayfmt was launched from a file manager, that output goes nowhere, so the
/// same text is also written to a temporary file and opened in the system's default
/// text editor. This keeps the result visible without a console.
fn display_text(payload: &[u8]) -> Result<(), DecayError> {
    let text = String::from_utf8_lossy(payload);
    print!("{text}");
    // Ensure the output ends on its own line so the shell prompt does not glue to the
    // decayed text when the payload has no trailing newline of its own.
    if !text.ends_with('\n') {
        println!();
    }

    if std::io::stdout().is_terminal() {
        return Ok(());
    }

    let viewer_path = temporary_output_path("txt");
    std::fs::write(&viewer_path, text.as_bytes()).map_err(|error| DecayError::Io {
        context: format!("open: write display text '{}'", viewer_path.display()),
        source: error,
    })?;
    open_in_default_app(&viewer_path)
}

/// Re-encodes a corrupted RGBA payload to a temporary PNG and opens it in the
/// system's default image viewer.
///
/// The raw payload carries no dimensions of its own, so the header's width and
/// height are required to interpret it. A payload whose length does not match those
/// dimensions is rejected as a size mismatch rather than displayed partially.
fn display_image(payload: &[u8], dimensions: ImageDimensions) -> Result<(), DecayError> {
    let expected = (dimensions.width as usize)
        .saturating_mul(dimensions.height as usize)
        .saturating_mul(RGBA_BYTES_PER_PIXEL);
    let image = image::RgbaImage::from_raw(dimensions.width, dimensions.height, payload.to_vec())
        .ok_or(DecayError::PayloadSizeMismatch {
        expected,
        found: payload.len(),
    })?;

    let viewer_path = temporary_output_path("png");
    image
        .save(&viewer_path)
        .map_err(|error| DecayError::ImageEncode {
            context: format!(
                "open: encode display png '{}': {}",
                viewer_path.display(),
                error
            ),
        })?;

    open_in_default_app(&viewer_path)
}

/// Builds a unique path in the system temp directory for a display file with the
/// given extension. The viewer is launched asynchronously so this file cannot be
/// deleted immediately; instead every open sweeps the previous ones via
/// [`cleanup_old_view_files`], so old snapshots do not accumulate.
fn temporary_output_path(extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("decayfmt_view_{nanos}.{extension}"))
}

/// Best-effort removal of the temporary view files left by previous opens.
///
/// Displaying a corrupted payload requires writing it to a temporary file for the
/// system viewer, and those files linger as snapshots of past decay states. Since the
/// format's whole point is that there is no recovery to an earlier state, the tool
/// must not quietly leave recoverable copies of less-corrupted states lying around. On
/// each open we sweep the old ones. Failures are ignored: a file still held open by a
/// viewer simply survives until the next run.
fn cleanup_old_view_files() {
    if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("decayfmt_view_") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

/// Hands a file to the operating system's default application for its type, used
/// for both the display PNG and the display text file.
///
/// Each platform exposes a different one-shot "open with the default application"
/// command. The application is spawned and not waited on, so it stays open after
/// this returns. A failure to launch is reported, though by this point the
/// corruption has already been written to disk.
fn open_in_default_app(path: &Path) -> Result<(), DecayError> {
    let spawn_result = if cfg!(target_os = "windows") {
        // On Windows, start is a cmd builtin; its first quoted argument is treated
        // as a window title, so an empty title is passed before the file path.
        Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(path)
            .spawn()
    } else if cfg!(target_os = "macos") {
        Command::new("open").arg(path).spawn()
    } else {
        Command::new("xdg-open").arg(path).spawn()
    };

    spawn_result
        .map(|_child| ())
        .map_err(|error| DecayError::Io {
            context: format!("open: launch default viewer for '{}'", path.display()),
            source: error,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::{encode_file, encode_v2};
    use crate::tpm::{CounterInfo, FakeTpm, TpmContext};
    use std::fs;
    use std::net::TcpListener;
    use std::process::{Child, Command, Stdio};
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier, Mutex,
    };
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tss_esapi::TctiNameConf;

    /// Builds a unique path in the system temp directory so concurrent test runs do
    /// not collide. The suffix carries the extension the test needs.
    fn unique_temp_path(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("decayfmt_open_test_{nanos}_{suffix}"))
    }

    #[test]
    fn open_changes_the_payload_but_never_the_header_on_disk() {
        // Encode a text file, capture its clean payload and header, open it, then
        // confirm the payload bytes on disk changed while the header bytes did not.
        let source = vec![b'a'; 4096];
        let input = unique_temp_path("source.txt");
        let decay_file = unique_temp_path("note.tdcy5");
        fs::write(&input, &source).expect("write test source");
        encode_file(&input, &decay_file).expect("encode should succeed");

        let before = fs::read(&decay_file).expect("read encoded file");
        let header_before = before[..HEADER_SIZE].to_vec();
        let payload_before = before[HEADER_SIZE..].to_vec();

        // decay_in_place is the persisted half of open, without the display step,
        // so the test exercises the corruption write without spawning a viewer.
        decay_in_place(&decay_file).expect("decay should succeed");

        let after = fs::read(&decay_file).expect("read opened file");
        assert_eq!(
            &after[..HEADER_SIZE],
            header_before.as_slice(),
            "the header bytes on disk must be untouched by open"
        );
        assert_ne!(
            &after[HEADER_SIZE..],
            payload_before.as_slice(),
            "payload must differ on disk after open"
        );
        assert_eq!(
            after.len(),
            before.len(),
            "in-place payload overwrite must not change the file length"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&decay_file);
    }

    #[test]
    fn mismatched_extension_and_header_type_is_refused() {
        // Encode an image (idcy), then present the same bytes under a text (tdcy) name.
        // The header says image, the extension says text, so open must refuse.
        let source_image = image::RgbaImage::from_fn(2, 2, |_, _| image::Rgba([1, 2, 3, 255]));
        let input = unique_temp_path("source.png");
        let image_file = unique_temp_path("photo.idcy3");
        let mismatched = unique_temp_path("photo.tdcy3");
        source_image.save(&input).expect("save test png");
        encode_file(&input, &image_file).expect("encode image should succeed");

        let bytes = fs::read(&image_file).expect("read image decayfmt file");
        fs::write(&mismatched, &bytes).expect("write mismatched-name copy");

        assert!(
            matches!(
                decay_in_place(&mismatched),
                Err(DecayError::MismatchedFileType { .. })
            ),
            "a file whose extension and header disagree must be refused"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&image_file);
        let _ = fs::remove_file(&mismatched);
    }

    // Restoring writability after the test uses set_readonly(false), which clippy
    // warns is platform-dependent. That is acceptable here: it only exists so the
    // read-only test file can be deleted again on platforms that need it.
    #[allow(clippy::permissions_set_readonly_false)]
    #[test]
    fn read_only_file_is_refused() {
        let input = unique_temp_path("source.txt");
        let decay_file = unique_temp_path("note.tdcy3");
        fs::write(&input, b"some text").expect("write test source");
        encode_file(&input, &decay_file).expect("encode should succeed");

        let mut permissions = fs::metadata(&decay_file)
            .expect("stat decay file")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&decay_file, permissions).expect("set read-only");

        assert!(
            matches!(
                decay_in_place(&decay_file),
                Err(DecayError::ReadOnly { .. })
            ),
            "a read-only file must be refused"
        );

        // Restore writability so the file can be cleaned up.
        let mut permissions = fs::metadata(&decay_file)
            .expect("stat decay file")
            .permissions();
        permissions.set_readonly(false);
        let _ = fs::set_permissions(&decay_file, permissions);
        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&decay_file);
    }

    #[test]
    fn wrong_magic_is_refused() {
        // A writable file with a valid x suffix but bogus header bytes must be
        // refused at header validation, after the writability check passes.
        let decay_file = unique_temp_path("bogus.tdcy3");
        fs::write(&decay_file, [0u8; 32]).expect("write bogus file");

        assert!(
            matches!(
                decay_in_place(&decay_file),
                Err(DecayError::WrongMagic { .. })
            ),
            "a file without the magic bytes must be refused"
        );

        let _ = fs::remove_file(&decay_file);
    }

    #[test]
    fn unrecognized_name_is_refused_before_touching_the_file() {
        // The path need not exist: the filename convention is checked before any file
        // access, and a plain .txt name is not a decayfmt name at all.
        let missing = Path::new("this_file_does_not_exist.txt");
        assert!(matches!(
            decay_in_place(missing),
            Err(DecayError::UnrecognizedExtension { .. })
        ));
    }

    #[test]
    fn v2_file_is_detected_by_magic() {
        // A DCF2 magic identifies a v2 file regardless of its name.
        let v2_path = unique_temp_path("detect_v2.idcy");
        fs::write(&v2_path, crate::format::MAGIC_V2).expect("write v2-magic file");
        assert!(file_is_v2(&v2_path).expect("detect v2 magic"));

        // A DCYF magic is a v1 file; a bare .tdcy name must not flip it to v2.
        let v1_path = unique_temp_path("detect_v1.tdcy");
        fs::write(&v1_path, crate::format::MAGIC).expect("write v1-magic file");
        assert!(!file_is_v2(&v1_path).expect("reject v1 magic"));

        // A too-short file cannot be a v2 file; it is handed to the v1 path to report.
        let short_path = unique_temp_path("detect_short.bin");
        fs::write(&short_path, b"DC").expect("write short file");
        assert!(!file_is_v2(&short_path).expect("reject short file"));

        let _ = fs::remove_file(&v2_path);
        let _ = fs::remove_file(&v1_path);
        let _ = fs::remove_file(&short_path);
    }

    #[test]
    fn open_index_first_open_is_zero() {
        assert_eq!(
            open_index_for(10, 10, 5, 0x0150_1234).expect("first open"),
            0
        );
    }

    #[test]
    fn open_index_counts_prior_opens() {
        assert_eq!(
            open_index_for(13, 10, 5, 0x0150_1234).expect("third open"),
            3
        );
    }

    #[test]
    fn open_index_last_allowed_open_is_n_max_minus_one() {
        assert_eq!(
            open_index_for(14, 10, 5, 0x0150_1234).expect("last valid open"),
            4
        );
    }

    #[test]
    fn open_index_rejects_rollback() {
        assert!(matches!(
            open_index_for(9, 10, 5, 0x0150_1234),
            Err(DecayError::NvCounter { .. })
        ));
    }

    #[test]
    fn open_index_rejects_exhausted() {
        // counter reaching c0 + n_max means the file is fully spent.
        assert!(matches!(
            open_index_for(15, 10, 5, 0x0150_1234),
            Err(DecayError::NvCounter { .. })
        ));
    }

    #[test]
    fn v2_text_encode_then_open_succeeds() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"hello, v2 world").expect("write v2 text source");

        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 10, &mut fake).expect("v2 text encode");

        let (file_type, _dimensions, degraded) =
            open_v2_processing(&output, &mut fake).expect("v2 text open");
        assert_eq!(file_type, FileType::Text);
        // The first open is index 0, so degradation is zero: the plaintext is pristine.
        assert_eq!(degraded, b"hello, v2 world".to_vec());

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_image_encode_then_open_succeeds() {
        let (width, height) = (3u32, 2u32);
        let source = image::RgbaImage::from_fn(width, height, |x, y| {
            image::Rgba([(x * 20) as u8, (y * 30) as u8, 40, 255])
        });
        let input = unique_temp_path("v2_src.png");
        let output = unique_temp_path("v2_out.idcy");
        source.save(&input).expect("save v2 image source");

        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 10, &mut fake).expect("v2 image encode");

        let (file_type, dimensions, degraded) =
            open_v2_processing(&output, &mut fake).expect("v2 image open");
        assert_eq!(file_type, FileType::Image);
        assert_eq!(dimensions.width, width);
        assert_eq!(dimensions.height, height);
        assert_eq!(degraded.len(), width as usize * height as usize * 4);

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_default_n_max_is_ten() {
        assert_eq!(crate::encode::DEFAULT_N_MAX, 10);

        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"x").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, crate::encode::DEFAULT_N_MAX, &mut fake).expect("encode");

        let bytes = fs::read(&output).expect("read encoded");
        let (header, _consumed) = HeaderV2::read(&bytes).expect("parse v2 header");
        assert_eq!(header.n_max, crate::encode::DEFAULT_N_MAX);

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_n_max_three_allows_three_opens_then_fails() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"abc").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 3, &mut fake).expect("encode n_max=3");

        for expected in 0..3 {
            open_v2_processing(&output, &mut fake)
                .unwrap_or_else(|e| panic!("open {expected} should succeed: {e}"));
        }
        assert!(
            matches!(
                open_v2_processing(&output, &mut fake),
                Err(DecayError::NvCounter { .. })
            ),
            "the 4th open must be refused as exhausted"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_file_is_byte_for_byte_unchanged_across_opens() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"some payload").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 10, &mut fake).expect("encode");

        let before = fs::read(&output).expect("read encoded file");
        for _ in 0..3 {
            open_v2_processing(&output, &mut fake).expect("open succeeds");
        }
        let after = fs::read(&output).expect("read after opens");
        assert_eq!(
            before, after,
            "the v2 artifact must be byte-for-byte unchanged by successful opens"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_file_is_unchanged_after_exhaustion() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"payload").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 3, &mut fake).expect("encode n_max=3");

        let before = fs::read(&output).expect("read encoded file");
        for _ in 0..3 {
            open_v2_processing(&output, &mut fake).expect("open succeeds");
        }
        assert!(matches!(
            open_v2_processing(&output, &mut fake),
            Err(DecayError::NvCounter { .. })
        ));
        let after = fs::read(&output).expect("read after exhaustion");
        assert_eq!(
            before, after,
            "the exhausted artifact must remain byte-for-byte unchanged"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_modified_ciphertext_is_rejected() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"secret payload").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 10, &mut fake).expect("encode");

        let mut bytes = fs::read(&output).expect("read encoded file");
        let (_, header_len) = HeaderV2::read(&bytes).expect("parse header");
        assert!(header_len < bytes.len(), "file must carry ciphertext");
        bytes[header_len] ^= 0xFF; // flip the first ciphertext byte
        fs::write(&output, &bytes).expect("write tampered file");

        assert!(
            matches!(
                open_v2_processing(&output, &mut fake),
                Err(DecayError::Crypto { .. })
            ),
            "a modified ciphertext must fail AES-GCM authentication"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_modified_authenticated_header_field_is_rejected() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"payload").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 10, &mut fake).expect("encode");

        let mut bytes = fs::read(&output).expect("read encoded file");
        // payload_nonce is the last fixed field, at offset HEADER_V2_FIXED_LEN - 12 (31).
        let nonce_offset = crate::format::HEADER_V2_FIXED_LEN - 12;
        bytes[nonce_offset] ^= 0xFF;
        fs::write(&output, &bytes).expect("write tampered header");

        assert!(
            matches!(
                open_v2_processing(&output, &mut fake),
                Err(DecayError::Crypto { .. })
            ),
            "a modified authenticated header field must fail AES-GCM authentication"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_mismatched_extension_and_header_type_is_rejected() {
        let (width, height) = (2u32, 2u32);
        let source = image::RgbaImage::from_fn(width, height, |_, _| image::Rgba([1, 2, 3, 255]));
        let input = unique_temp_path("v2_src.png");
        let image_file = unique_temp_path("v2_img.idcy");
        let mismatched = unique_temp_path("v2_img.tdcy");
        source.save(&input).expect("save v2 image source");

        let mut fake = FakeTpm::new();
        encode_v2(&input, &image_file, 10, &mut fake).expect("v2 image encode");

        let bytes = fs::read(&image_file).expect("read image v2 file");
        fs::write(&mismatched, &bytes).expect("write mismatched-name copy");

        assert!(
            matches!(
                open_v2_processing(&mismatched, &mut fake),
                Err(DecayError::MismatchedFileType { .. })
            ),
            "a v2 file whose extension and header type disagree must be refused"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&image_file);
        let _ = fs::remove_file(&mismatched);
    }

    /// Returns the `nv_index` stored in a v2 file's header.
    fn v2_nv_index(path: &Path) -> u32 {
        let bytes = fs::read(path).expect("read v2 file");
        let (header, _consumed) = HeaderV2::read(&bytes).expect("parse v2 header");
        header.nv_index
    }

    #[test]
    fn v2_counter_increments_before_unseal() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"payload for ordering").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 10, &mut fake).expect("encode");
        fake.call_log.clear();

        fake.fail_unseal = true;
        let result = open_v2_processing(&output, &mut fake);
        assert!(
            matches!(result, Err(DecayError::Tpm { .. })),
            "unseal must fail"
        );
        assert_eq!(
            fake.call_log,
            vec!["validate", "read", "increment", "unseal"]
        );
        assert_eq!(
            fake.read_counter(v2_nv_index(&output)).unwrap(),
            1,
            "counter must advance by exactly one despite the unseal failure"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_unseal_failure_still_consumes_an_access() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"0123456789abcdef").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 10, &mut fake).expect("encode");
        fake.call_log.clear();

        // First open fails after increment (during unseal), consuming one access.
        fake.fail_unseal = true;
        assert!(matches!(
            open_v2_processing(&output, &mut fake),
            Err(DecayError::Tpm { .. })
        ));
        assert_eq!(
            fake.call_log,
            vec!["validate", "read", "increment", "unseal"]
        );
        assert_eq!(fake.read_counter(v2_nv_index(&output)).unwrap(), 1);

        // Disable the failure; the next open is index 1 (counter already 1), not index 0.
        fake.fail_unseal = false;
        fake.call_log.clear();
        let (file_type, _dims, _degraded) =
            open_v2_processing(&output, &mut fake).expect("second open must succeed");
        assert_eq!(file_type, FileType::Text);
        assert_eq!(
            fake.call_log,
            vec!["validate", "read", "increment", "unseal"]
        );
        assert_eq!(fake.read_counter(v2_nv_index(&output)).unwrap(), 2);

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_increment_failure_does_not_release_or_decrypt() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"secret").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 10, &mut fake).expect("encode");
        fake.call_log.clear();

        fake.fail_increment = true;
        let result = open_v2_processing(&output, &mut fake);
        assert!(
            matches!(result, Err(DecayError::NvCounter { .. })),
            "increment failure must fail closed"
        );
        // Unseal was never reached; increment was attempted but the counter did not advance.
        assert_eq!(fake.call_log, vec!["validate", "read", "increment"]);
        assert_eq!(
            fake.read_counter(v2_nv_index(&output)).unwrap(),
            0,
            "counter must not advance when increment fails"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_exhausted_file_does_not_unseal() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"payload").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 3, &mut fake).expect("encode n_max=3");

        for _ in 0..3 {
            open_v2_processing(&output, &mut fake).expect("open succeeds");
        }
        fake.call_log.clear();
        fake.fail_unseal = true;

        let result = open_v2_processing(&output, &mut fake);
        assert!(
            matches!(result, Err(DecayError::NvCounter { .. })),
            "exhaustion must win over a configured unseal failure"
        );
        assert_eq!(fake.call_log, vec!["validate", "read"]);
        assert_eq!(fake.read_counter(v2_nv_index(&output)).unwrap(), 3);

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_validate_and_read_failures_precede_increment() {
        let input = unique_temp_path("v2_src.txt");
        let output = unique_temp_path("v2_out.tdcy");
        fs::write(&input, b"payload").expect("write source");
        let mut fake = FakeTpm::new();
        encode_v2(&input, &output, 10, &mut fake).expect("encode");
        fake.call_log.clear();

        fake.fail_validate = true;
        assert!(matches!(
            open_v2_processing(&output, &mut fake),
            Err(DecayError::NvCounter { .. })
        ));
        assert_eq!(fake.call_log, vec!["validate"]);
        assert_eq!(fake.read_counter(v2_nv_index(&output)).unwrap(), 0);
        fake.call_log.clear();

        fake.fail_validate = false;
        fake.fail_read = true;
        assert!(matches!(
            open_v2_processing(&output, &mut fake),
            Err(DecayError::NvCounter { .. })
        ));
        assert_eq!(fake.call_log, vec!["validate", "read"]);
        // Disable the read failure so we can inspect the counter (it must be unchanged).
        fake.fail_read = false;
        assert_eq!(fake.read_counter(v2_nv_index(&output)).unwrap(), 0);

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }

    #[test]
    fn v2_real_swtpm_lifecycle_expires_after_n_max() {
        // Connect to the real software TPM. This FAILS (does not skip) if swtpm is unavailable.
        let conf: TctiNameConf = "swtpm:host=127.0.0.1,port=2321"
            .parse()
            .expect("swtpm TCTI name must parse");
        let mut tpm = TpmContext::connect_with_tcti(conf)
            .expect("swtpm must be running on 127.0.0.1:2321 for the real v2 lifecycle test");

        let input = unique_temp_path("swtpm_src.txt");
        let output = unique_temp_path("swtpm_out.tdcy");
        fs::write(&input, b"real swtpm lifecycle payload").expect("write source");

        // Encode with n_max = 3; encode itself consumes no access.
        encode_v2(&input, &output, 3, &mut tpm).expect("v2 encode against the software TPM");

        let before = fs::read(&output).expect("read encoded v2 file");

        // Opens 0, 1 and 2 must succeed; the 4th open (index 3) must be exhausted.
        for open_index in 0..3u32 {
            let (file_type, _dims, degraded) = open_v2_processing(&output, &mut tpm)
                .unwrap_or_else(|e| panic!("v2 open {open_index} should succeed: {e}"));
            assert_eq!(file_type, FileType::Text);
            if open_index == 0 {
                // open_index 0 degrades nothing, so the plaintext is pristine.
                assert_eq!(degraded, b"real swtpm lifecycle payload".to_vec());
            }
        }
        assert!(
            matches!(
                open_v2_processing(&output, &mut tpm),
                Err(DecayError::NvCounter { .. })
            ),
            "the 4th open must be refused as exhausted"
        );

        let after = fs::read(&output).expect("read v2 file after opens");
        assert_eq!(
            before, after,
            "the v2 artifact must be byte-for-byte unchanged across opens and exhaustion"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }
    /// Reserves a free loopback TCP port by binding an ephemeral socket. The listener is dropped
    /// immediately, so there is a tiny race before swtpm binds it.
    fn free_tcp_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("bind an ephemeral loopback port")
            .local_addr()
            .expect("read the ephemeral port")
            .port()
    }

    /// Returns `(server, control)` loopback ports for swtpm. `tcti-swtpm` infers the control port
    /// as `server + 1`, so pick a server port whose neighbour is also free and use it as the
    /// control port: an explicitly supplied `ctrlport` key is not accepted by this TCTI.
    fn two_free_tcp_ports() -> (u16, u16) {
        loop {
            let server = free_tcp_port();
            if server == u16::MAX {
                continue;
            }
            let ctrl = server + 1;
            if TcpListener::bind(("127.0.0.1", ctrl)).is_ok() {
                return (server, ctrl);
            }
        }
    }

    /// Polls `TpmContext::connect_with_tcti` until the swtpm on `port` answers, or panics. Unlike
    /// the tolerant smoke test this never silently skips: it only returns on a live TPM.
    fn connect_swtpm(port: u16) -> TpmContext {
        for _ in 0..200 {
            let conf: TctiNameConf = format!("swtpm:host=127.0.0.1,port={port}")
                .parse()
                .expect("swtpm TCTI name must parse");
            if let Ok(tpm) = TpmContext::connect_with_tcti(conf) {
                return tpm;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("swtpm never became ready on 127.0.0.1:{port}; ensure `swtpm` is installed and its state dir is writable");
    }

    /// Owns the swtpm child the test spawned so it never touches any unrelated swtpm process.
    /// `Drop` guarantees the test's own process is reaped even if the test panics.
    struct SwtpmProc {
        child: Child,
    }

    impl SwtpmProc {
        fn spawn(state_dir: &Path, server_port: u16, ctrl_port: u16) -> SwtpmProc {
            let child = Command::new("swtpm")
                .args(["socket", "--tpm2"])
                .arg("--tpmstate")
                .arg(format!("dir={}", state_dir.display()))
                .arg("--ctrl")
                .arg(format!("type=tcp,port={ctrl_port}"))
                .arg("--server")
                .arg(format!("type=tcp,port={server_port}"))
                .args(["--flags", "startup-clear"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap_or_else(|error| panic!("failed to start the test's own swtpm: {error}"));
            SwtpmProc { child }
        }

        /// Gracefully stops swtpm (SIGTERM) so it flushes its state directory, with a short grace
        /// period before force-killing so a hung test never blocks indefinitely.
        fn stop(&mut self) {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(self.child.id().to_string())
                .status();
            for _ in 0..50 {
                if self.child.try_wait().ok().flatten().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for SwtpmProc {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn v2_real_swtpm_persistence_survives_restart() {
        // Use our OWN swtpm on a dedicated state directory + ports so we never touch the shared
        // swtpm on 2321 nor any unrelated process.
        let state_dir = unique_temp_path("swtpm_state_dir");
        fs::create_dir_all(&state_dir).expect("create swtpm state dir");
        let (server_port, ctrl_port) = two_free_tcp_ports();

        let mut tp = SwtpmProc::spawn(&state_dir, server_port, ctrl_port);
        let mut tpm = connect_swtpm(server_port);

        // A long payload makes the degraded open-1 plaintext essentially guaranteed to differ
        // from the pristine open-0 plaintext, proving the open index advanced (not index 0).
        let payload: Vec<u8> = b"decayfmt swtpm persistence proof "
            .iter()
            .copied()
            .cycle()
            .take(512)
            .collect();
        let input = unique_temp_path("swtpm_persist_src.txt");
        let output = unique_temp_path("swtpm_persist_out.tdcy");
        fs::write(&input, &payload).expect("write source");
        encode_v2(&input, &output, 3, &mut tpm).expect("v2 encode (before restart)");

        let nv_index = v2_nv_index(&output);
        let before = fs::read(&output).expect("read encoded v2 file");

        // First open (index 0): succeeds and is pristine.
        let (ft0, _d0, p0) = open_v2_processing(&output, &mut tpm)
            .unwrap_or_else(|e| panic!("first open should succeed: {e}"));
        assert_eq!(ft0, FileType::Text, "first open is a text file");
        assert_eq!(p0, payload, "open 0 is pristine (index 0 degrades nothing)");
        assert_eq!(
            tpm.read_counter(nv_index).unwrap(),
            1,
            "counter is 1 after the first open"
        );

        // Stop the test's own swtpm, then restart it against the SAME state dir + TCTI endpoint.
        tp.stop();
        tp = SwtpmProc::spawn(&state_dir, server_port, ctrl_port);

        // Reconnect: the sealed object and NV counter must both still be valid after the restart.
        let mut tpm = connect_swtpm(server_port);
        assert_eq!(
            tpm.read_counter(nv_index).unwrap(),
            1,
            "the NV counter must survive the swtpm restart"
        );

        // Second open (index 1): succeeds and is degraded, i.e. NOT index 0.
        let (ft1, _d1, p1) = open_v2_processing(&output, &mut tpm)
            .unwrap_or_else(|e| panic!("second open after restart should succeed: {e}"));
        assert_eq!(ft1, FileType::Text, "second open is a text file");
        assert_ne!(
            p1, payload,
            "open 1 is the next index (degraded), not index 0"
        );
        assert_ne!(p1, p0, "the two opens must yield different plaintexts");
        assert_eq!(
            tpm.read_counter(nv_index).unwrap(),
            2,
            "counter is 2 after the second open"
        );

        let after = fs::read(&output).expect("read v2 file after the restart open");
        assert_eq!(
            before, after,
            "the v2 artifact must be byte-for-byte unchanged across the restart"
        );

        tp.stop();
        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
        let _ = fs::remove_dir_all(&state_dir);
    }
    /// A thread-safe, deterministic [`Tpm`] used only to drive concurrent opens of the same
    /// file. Clones share a single monotonic counter (modelling a real TPM counter shared
    /// across processes) and a single content key, so distinct opens observe distinct counter
    /// values. `read_counter` and `increment_counter` are each individually atomic but are NOT
    /// atomic as a pair; the advisory lock taken by [`open_v2_processing`] is what serializes
    /// the pair.
    #[cfg(test)]
    #[derive(Clone)]
    struct CountingTpm {
        counter: Arc<AtomicU64>,
        reads: Arc<Mutex<Vec<u64>>>,
        key: Arc<Mutex<[u8; 32]>>,
        nv_index: u32,
    }

    #[cfg(test)]
    impl CountingTpm {
        fn new() -> Self {
            CountingTpm {
                counter: Arc::new(AtomicU64::new(0)),
                reads: Arc::new(Mutex::new(Vec::new())),
                key: Arc::new(Mutex::new([0u8; 32])),
                nv_index: 0x0100_0001,
            }
        }
    }

    #[cfg(test)]
    impl Tpm for CountingTpm {
        fn seal_content_key(
            &mut self,
            content_key: &ContentKey,
        ) -> Result<(Vec<u8>, Vec<u8>), DecayError> {
            let mut raw = [0u8; 32];
            raw.copy_from_slice(content_key.as_bytes());
            *self.key.lock().unwrap() = raw;
            Ok((b"sealed-pub".to_vec(), b"sealed-priv".to_vec()))
        }

        fn allocate_counter(&mut self) -> Result<CounterInfo, DecayError> {
            self.counter.store(0, Ordering::SeqCst);
            Ok(CounterInfo {
                nv_index: self.nv_index,
                c0: 0,
            })
        }

        fn validate_counter(&mut self, _nv_index: u32) -> Result<(), DecayError> {
            Ok(())
        }

        fn read_counter(&mut self, _nv_index: u32) -> Result<u64, DecayError> {
            let value = self.counter.load(Ordering::SeqCst);
            self.reads.lock().unwrap().push(value);
            Ok(value)
        }

        fn increment_counter(&mut self, _nv_index: u32) -> Result<(), DecayError> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn unseal_content_key(
            &mut self,
            _sealed_pub: &[u8],
            _sealed_priv: &[u8],
        ) -> Result<[u8; 32], DecayError> {
            Ok(*self.key.lock().unwrap())
        }
    }

    #[test]
    fn v2_open_index_is_unique_across_concurrent_opens() {
        const OPENS: usize = 16;

        let input = unique_temp_path("v2_concurrent_src.txt");
        let output = unique_temp_path("v2_concurrent_out.tdcy");
        fs::write(&input, b"payload for concurrent open indexing").expect("write source");
        let mut encoder = CountingTpm::new();
        encode_v2(&input, &output, OPENS as u32, &mut encoder).expect("v2 encode");

        // Fire OPENS concurrent opens of the same .tdcy, all released at once. Because
        // open_v2_processing locks the file for the read-counter -> increment-counter critical
        // section, each open observes a distinct counter value and therefore a distinct
        // open_index. Without that lock these reads race and can yield duplicate open indexes.
        let barrier = Arc::new(Barrier::new(OPENS));
        let mut handles = Vec::new();
        for _ in 0..OPENS {
            let mut tpm = encoder.clone();
            let output = output.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                open_v2_processing(&output, &mut tpm).expect("concurrent open should succeed")
            }));
        }
        for handle in handles {
            handle.join().expect("open thread must not panic");
        }

        let mut reads = encoder.reads.lock().unwrap().clone();
        assert_eq!(
            reads.len(),
            OPENS,
            "there must be exactly one counter read per open"
        );
        reads.sort_unstable();
        let expected: Vec<u64> = (0..OPENS as u64).collect();
        assert_eq!(
            reads, expected,
            "concurrent opens must receive distinct, sequential open indexes"
        );
        assert_eq!(
            encoder.counter.load(Ordering::SeqCst),
            OPENS as u64,
            "the TPM counter must advance exactly once per open"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }
}
