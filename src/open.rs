//! Open a decayfmt file: corrupt it in place on disk, then display it.
//!
//! This module owns the entire open flow and all of its file I/O. The order of
//! operations is the core of the format contract and must not be reordered: x is
//! parsed from the filename, the file is confirmed writable, the payload is
//! corrupted, the corrupted bytes are written back to disk, and only then is the
//! result displayed. Corruption is paid before display, so a crash mid-flow can
//! never hand back a free, uncorrupted read.

use crate::corrupt::corrupt;
use crate::error::DecayError;
use crate::format::{Header, ImageDimensions, HEADER_SIZE};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Filename extension prefix that precedes x for an image, for example `idcy3`.
const IMAGE_EXTENSION_PREFIX: &str = "idcy";

/// Filename extension prefix that precedes x for text, for example `tdcy7`.
const TEXT_EXTENSION_PREFIX: &str = "tdcy";

/// Number of bytes per pixel in an RGBA payload, used to size the display image.
const RGBA_BYTES_PER_PIXEL: usize = 4;

/// Parses the instability value x from a decayfmt filename.
///
/// x lives in the extension as `idcy<x>` or `tdcy<x>`, where x is a positive
/// integer. x is read from the filename and nowhere else. A filename whose
/// extension has no recognized prefix or no integer suffix yields FilenameNoX; a
/// suffix that parses to zero yields XNotPositive. Returns x as f64 because that is
/// what the corruption math consumes.
fn parse_x_from_filename(path: &Path) -> Result<f64, DecayError> {
    let filename = path.to_string_lossy().into_owned();
    let no_x = || DecayError::FilenameNoX {
        filename: filename.clone(),
    };

    let extension = path.extension().and_then(|raw| raw.to_str()).ok_or_else(no_x)?;
    let digits = extension
        .strip_prefix(IMAGE_EXTENSION_PREFIX)
        .or_else(|| extension.strip_prefix(TEXT_EXTENSION_PREFIX))
        .ok_or_else(no_x)?;

    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(no_x());
    }

    let value: u32 = digits.parse().map_err(|_| no_x())?;
    if value == 0 {
        return Err(DecayError::XNotPositive {
            value: f64::from(value),
        });
    }
    Ok(f64::from(value))
}

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
    let x = parse_x_from_filename(path)?;
    ensure_writable(path)?;

    let mut file_bytes = std::fs::read(path).map_err(|error| DecayError::Io {
        context: format!("open: read '{}'", path.display()),
        source: error,
    })?;

    let header = Header::read(&file_bytes)?;

    // Corrupt the payload in place. The header occupies the first HEADER_SIZE bytes
    // and is left untouched; everything after it is the payload.
    corrupt(&mut file_bytes[HEADER_SIZE..], header.file_type, x);

    // Persist the corruption. This is the point of no return: once this write
    // lands, the previous payload state is gone for good.
    std::fs::write(path, &file_bytes).map_err(|error| DecayError::Io {
        context: format!("open: write corrupted payload to '{}'", path.display()),
        source: error,
    })?;

    Ok((header, file_bytes))
}

/// Opens a decayfmt file: corrupts its payload in place on disk, then displays it.
///
/// Upholds the contract ordering: the file is corrupted and persisted first, then
/// displayed. Dimensions are present exactly for images, so their presence selects
/// the display path.
pub fn open_file(path: &Path) -> Result<(), DecayError> {
    let (header, file_bytes) = decay_in_place(path)?;
    let payload = &file_bytes[HEADER_SIZE..];
    match header.dimensions {
        Some(dimensions) => display_image(payload, dimensions),
        None => display_text(payload),
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
    print!("{}", text);

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
    image.save(&viewer_path).map_err(|error| DecayError::ImageEncode {
        context: format!(
            "open: encode display png '{}': {}",
            viewer_path.display(),
            error
        ),
    })?;

    open_in_default_app(&viewer_path)
}

/// Builds a unique path in the system temp directory for a display file with the
/// given extension. The file is left for the operating system to reclaim, since the
/// viewer is launched asynchronously and we cannot know when it has finished
/// reading the file.
fn temporary_output_path(extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("decayfmt_view_{}.{}", nanos, extension))
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

    spawn_result.map(|_child| ()).map_err(|error| DecayError::Io {
        context: format!("open: launch default viewer for '{}'", path.display()),
        source: error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::encode_file;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Builds a unique path in the system temp directory so concurrent test runs do
    /// not collide. The suffix carries the extension the test needs.
    fn unique_temp_path(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("decayfmt_open_test_{}_{}", nanos, suffix))
    }

    #[test]
    fn x_is_parsed_from_image_and_text_extensions() {
        assert_eq!(
            parse_x_from_filename(Path::new("photo.idcy3")).expect("idcy3 parses"),
            3.0
        );
        assert_eq!(
            parse_x_from_filename(Path::new("note.tdcy12")).expect("tdcy12 parses"),
            12.0
        );
    }

    #[test]
    fn missing_or_malformed_x_is_refused() {
        for name in ["plain.png", "note.txt", "no_extension", "photo.idcy", "photo.idcyx"] {
            assert!(
                matches!(
                    parse_x_from_filename(Path::new(name)),
                    Err(DecayError::FilenameNoX { .. })
                ),
                "'{}' should yield FilenameNoX",
                name
            );
        }
    }

    #[test]
    fn zero_x_is_refused_as_not_positive() {
        assert!(matches!(
            parse_x_from_filename(Path::new("photo.idcy0")),
            Err(DecayError::XNotPositive { .. })
        ));
    }

    #[test]
    fn open_changes_the_payload_on_disk() {
        // Encode a text file, capture its clean payload, open it, then confirm the
        // payload bytes on disk are no longer what they were.
        let source = vec![b'a'; 4096];
        let input = unique_temp_path("source.txt");
        let decay_file = unique_temp_path("note.tdcy5");
        fs::write(&input, &source).expect("write test source");
        encode_file(&input, &decay_file, 5.0).expect("encode should succeed");

        let before = fs::read(&decay_file).expect("read encoded file");
        let payload_before = before[HEADER_SIZE..].to_vec();

        // decay_in_place is the persisted half of open, without the display step,
        // so the test exercises the corruption write without spawning a viewer.
        decay_in_place(&decay_file).expect("decay should succeed");

        let after = fs::read(&decay_file).expect("read opened file");
        let payload_after = &after[HEADER_SIZE..];
        assert_ne!(
            payload_after, payload_before,
            "payload must differ on disk after open"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&decay_file);
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
        encode_file(&input, &decay_file, 3.0).expect("encode should succeed");

        let mut permissions = fs::metadata(&decay_file)
            .expect("stat decay file")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&decay_file, permissions).expect("set read-only");

        assert!(
            matches!(decay_in_place(&decay_file), Err(DecayError::ReadOnly { .. })),
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
            matches!(decay_in_place(&decay_file), Err(DecayError::WrongMagic { .. })),
            "a file without the magic bytes must be refused"
        );

        let _ = fs::remove_file(&decay_file);
    }

    #[test]
    fn filename_without_x_is_refused_before_touching_the_file() {
        // The path need not exist: parsing x fails before any file access.
        let missing = Path::new("this_file_does_not_exist.txt");
        assert!(matches!(
            decay_in_place(missing),
            Err(DecayError::FilenameNoX { .. })
        ));
    }
}
