//! Open a decayfmt file: corrupt it in place on disk, then display it.
//!
//! This module owns the entire open flow and all of its file I/O. The order of
//! operations is fixed and must not be reordered: x is parsed from the filename, the
//! file is confirmed writable, the payload is corrupted, the corrupted bytes are
//! written back to disk, and only then is the result displayed. Corruption is written
//! before display, so a crash mid-flow cannot produce an uncorrupted read. The whole
//! read-modify-write sequence runs under an exclusive advisory lock on the file, so
//! overlapping opens each cost their own corruption instead of overwriting each other.

use crate::corrupt::corrupt;
use crate::error::DecayError;
use crate::format::{
    parse_filename, AudioSpec, Header, ImageDimensions, Metadata, AUDIO_BITS_PER_SAMPLE,
    AUDIO_BYTES_PER_SAMPLE, HEADER_SIZE,
};
use fs2::FileExt;
use std::fs::OpenOptions;
use std::io::{IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Number of bytes per pixel in an RGBA payload, used to size the display image.
const RGBA_BYTES_PER_PIXEL: usize = 4;

/// Confirms the file can be written before any corruption is attempted.
///
/// A read-only file cannot receive its corrupted payload, so this check runs before
/// any read or display and fails closed.
fn ensure_writable(path: &Path) -> Result<(), DecayError> {
    let metadata = std::fs::metadata(path).map_err(|error| DecayError::Io {
        context: format!("couldn't stat '{}'", path.display()),
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
/// This is the persisted half of the open flow: parse x, verify writability, corrupt
/// the payload, write it back. It performs no display, so the corruption it writes is
/// independent of the display path. The header is read but never changed; only the
/// payload is corrupted.
///
/// Public so embedding callers can commit an open without the display side of
/// `open_file`.
pub fn decay_in_place(path: &Path) -> Result<(Header, Vec<u8>), DecayError> {
    let (filename_type, x) = parse_filename(path)?;
    ensure_writable(path)?;

    // One handle serves the whole read, corrupt, and write-back sequence, held under an
    // exclusive advisory lock. Reading and writing through separate handles would leave
    // a window where two concurrent opens both read the same starting payload and the
    // later write discarded the earlier one, so the two opens together cost a single
    // corruption. The kernel releases the lock when the file is dropped or the process
    // exits, so a crash cannot leave it held.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| DecayError::Io {
            context: format!("couldn't open '{}'", path.display()),
            source: error,
        })?;
    file.lock_exclusive().map_err(|error| DecayError::Io {
        context: format!("couldn't lock '{}' for a single open", path.display()),
        source: error,
    })?;

    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes)
        .map_err(|error| DecayError::Io {
            context: format!("couldn't read '{}'", path.display()),
            source: error,
        })?;

    let header = Header::read(&file_bytes)?;

    // The extension prefix and the header must agree on the payload type. If they
    // disagree, for example an image file renamed to a .tdcy<x> name, refuse rather
    // than trusting either source.
    if filename_type != header.file_type {
        return Err(DecayError::MismatchedFileType {
            extension_kind: filename_type.label(),
            header_kind: header.file_type.label(),
        });
    }

    // Corrupt the payload in place. The header occupies the first HEADER_SIZE bytes
    // and is left untouched; everything after it is the payload.
    corrupt(&mut file_bytes[HEADER_SIZE..], header.file_type, x);

    // Persist the corruption by overwriting only the payload region in place, through
    // the same locked handle the payload was read from. The header bytes on disk are
    // never rewritten, and because corruption preserves length the file is never
    // truncated. The previous payload bytes are not kept anywhere. A crash mid-write
    // leaves a partially corrupted payload behind an intact header, so the file still
    // decays rather than bricking.
    file.seek(SeekFrom::Start(HEADER_SIZE as u64))
        .map_err(|error| DecayError::Io {
            context: format!("couldn't seek past the header in '{}'", path.display()),
            source: error,
        })?;
    file.write_all(&file_bytes[HEADER_SIZE..])
        .map_err(|error| DecayError::Io {
            context: format!(
                "couldn't write the corrupted payload to '{}'",
                path.display()
            ),
            source: error,
        })?;

    Ok((header, file_bytes))
}

/// Opens a decayfmt file: corrupts its payload in place on disk, then displays it.
///
/// The file is corrupted and persisted first, then displayed. The header's per-type
/// metadata selects the display path, so each payload type is presented with the
/// parameters it recorded at encode time.
pub fn open_file(path: &Path) -> Result<(), DecayError> {
    sweep_stale_view_files();
    let (header, file_bytes) = decay_in_place(path)?;
    let payload = &file_bytes[HEADER_SIZE..];
    match header.metadata {
        Metadata::Image(dimensions) => display_image(payload, dimensions),
        Metadata::Text => display_text(payload),
        Metadata::Audio(spec) => play_audio(payload, spec),
    }
}

/// Displays a corrupted text payload.
///
/// The payload may no longer be valid UTF-8 after corruption, so it is rendered
/// lossily: invalid byte sequences become the Unicode replacement character rather
/// than causing a failure.
///
/// The text is always written to stdout. When stdout is not a terminal, for example
/// when decayfmt was launched from a file manager, that output goes nowhere, so the
/// same text is also written to a temporary file and opened in the system's default
/// text editor. This keeps the result visible without a console.
fn display_text(payload: &[u8]) -> Result<(), DecayError> {
    let text = String::from_utf8_lossy(payload);
    print!("{}", text);
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
        context: format!("couldn't write display text '{}'", viewer_path.display()),
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
                "couldn't encode display png '{}': {}",
                viewer_path.display(),
                error
            ),
        })?;

    open_in_default_app(&viewer_path)
}

/// Re-encodes a corrupted PCM payload to a temporary WAV and opens it in the system's
/// default audio player.
///
/// The raw payload carries no playback parameters of its own, so the header's sample
/// rate, channel count, and bit depth are required to interpret it. WAV is used for the
/// same reason PNG is used for images: hound is pure Rust, so the binary stays
/// self-contained, and an uncompressed container reproduces the decayed samples exactly
/// rather than running them through a lossy encoder that would add its own artifacts.
///
/// A payload whose length is not a whole number of frames is rejected as a size
/// mismatch rather than played back partially.
fn play_audio(payload: &[u8], spec: AudioSpec) -> Result<(), DecayError> {
    if spec.bits_per_sample != AUDIO_BITS_PER_SAMPLE {
        return Err(DecayError::AudioEncode {
            context: format!(
                "expected {} bits per sample in the header, found {}",
                AUDIO_BITS_PER_SAMPLE, spec.bits_per_sample
            ),
        });
    }
    if spec.channels == 0 {
        return Err(DecayError::AudioEncode {
            context: "expected at least one audio channel in the header, found zero".to_string(),
        });
    }

    // Every frame holds one sample per channel, so the payload must divide evenly into
    // whole frames for the clip to be complete.
    let bytes_per_frame = AUDIO_BYTES_PER_SAMPLE * spec.channels as usize;
    // `manual_is_multiple_of` suggests `usize::is_multiple_of`, which is stable only
    // from Rust 1.87; the remainder test keeps the minimum supported Rust version low,
    // matching the same choice made in corrupt.rs.
    #[allow(unknown_lints, clippy::manual_is_multiple_of)]
    if payload.len() % bytes_per_frame != 0 {
        let whole_frames = payload.len() / bytes_per_frame;
        return Err(DecayError::PayloadSizeMismatch {
            expected: whole_frames.saturating_add(1) * bytes_per_frame,
            found: payload.len(),
        });
    }

    let viewer_path = temporary_output_path("wav");
    let encode_error = |message: String| DecayError::AudioEncode {
        context: format!(
            "couldn't encode playback wav '{}': {}",
            viewer_path.display(),
            message
        ),
    };

    let wav_spec = hound::WavSpec {
        channels: u16::from(spec.channels),
        sample_rate: spec.sample_rate,
        bits_per_sample: u16::from(spec.bits_per_sample),
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer = hound::WavWriter::create(&viewer_path, wav_spec)
        .map_err(|error| encode_error(error.to_string()))?;
    // `chunks_exact_to_as_chunks` suggests `slice::as_chunks`, which is stable only from
    // Rust 1.88; `chunks_exact` keeps the minimum supported Rust version low, matching
    // the same choice made in corrupt.rs.
    #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
    for sample in payload.chunks_exact(AUDIO_BYTES_PER_SAMPLE) {
        let value = i16::from_le_bytes([sample[0], sample[1]]);
        writer
            .write_sample(value)
            .map_err(|error| encode_error(error.to_string()))?;
    }
    writer
        .finalize()
        .map_err(|error| encode_error(error.to_string()))?;

    open_in_default_app(&viewer_path)
}

/// Builds a unique path in the system temp directory for a display file with the
/// given extension. The viewer is launched asynchronously so this file cannot be
/// deleted immediately; instead every open sweeps the previous ones via
/// [`sweep_stale_view_files`], so old snapshots do not accumulate.
fn temporary_output_path(extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("decayfmt_view_{}.{}", nanos, extension))
}

/// Best-effort removal of the temporary view files left by previous opens.
///
/// Displaying a corrupted payload requires writing it to a temporary file for the
/// system viewer, and those files persist as copies of earlier, less-corrupted payload
/// states. Every command sweeps them, not just a successful open, so an encode or a
/// failed open also clears whatever the last display left behind. Failures are ignored:
/// a file still held open by a viewer simply survives until the next run.
///
/// The file from the current open cannot be swept here, because the viewer is launched
/// asynchronously and needs it to outlive this process.
pub fn sweep_stale_view_files() {
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
/// for the display PNG, the display text file, and the playback WAV.
///
/// Each platform exposes a different one-shot "open with the default application"
/// command. The application is spawned and not waited on, so it stays open after
/// this returns. A failure to launch is reported as an error.
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
            context: format!(
                "couldn't launch the default viewer for '{}'",
                path.display()
            ),
            source: error,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::encode_file;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Builds a unique path in the system temp directory so concurrent test runs do
    /// not collide. The suffix carries the extension the test needs.
    ///
    /// The clock alone is not enough: tests run on parallel threads and some platforms
    /// tick coarsely, so two tests asking for the same suffix can read the same instant.
    /// The process id separates concurrent test binaries and the counter separates
    /// threads within one.
    fn unique_temp_path(suffix: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "decayfmt_open_test_{}_{}_{}_{}",
            std::process::id(),
            nanos,
            NEXT.fetch_add(1, Ordering::Relaxed),
            suffix
        ))
    }

    /// Builds a minimal 16-bit PCM WAV in memory so the audio tests do not need a
    /// fixture file on disk. `frames` is the number of samples per channel.
    fn wav_bytes(sample_rate: u32, channels: u16, frames: u32) -> Vec<u8> {
        let data_len = frames * u32::from(channels) * 2;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&(36 + data_len).to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt ");
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&channels.to_le_bytes());
        bytes.extend_from_slice(&sample_rate.to_le_bytes());
        bytes.extend_from_slice(&(sample_rate * u32::from(channels) * 2).to_le_bytes());
        bytes.extend_from_slice(&(channels * 2).to_le_bytes());
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&data_len.to_le_bytes());
        for frame in 0..frames {
            for _ in 0..channels {
                // A ramp rather than silence, so a corrupted byte is a changed byte.
                let sample = (frame % 30_000) as i16;
                bytes.extend_from_slice(&sample.to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn open_changes_the_payload_but_never_the_header_on_disk() {
        // The core of the format: decay is written to disk, the header is untouched,
        // and length is preserved. Checked for a text file and an audio file, since
        // audio must also keep its duration, sample rate, and channel count.
        let text_source = unique_temp_path("source.txt");
        fs::write(&text_source, vec![b'a'; 4096]).expect("write test source");
        let audio_source = unique_temp_path("source.wav");
        fs::write(&audio_source, wav_bytes(22_050, 1, 4_000)).expect("write test wav");

        for (source, name) in [(&text_source, "note.tdcy5"), (&audio_source, "clip.adcy10")] {
            let decay_file = unique_temp_path(name);
            encode_file(source, &decay_file).expect("encode should succeed");

            let before = fs::read(&decay_file).expect("read encoded file");
            // decay_in_place is the persisted half of open, without the display step,
            // so the test exercises the corruption write without spawning a viewer.
            decay_in_place(&decay_file).expect("decay should succeed");
            let after = fs::read(&decay_file).expect("read opened file");

            assert_eq!(
                &after[..HEADER_SIZE],
                &before[..HEADER_SIZE],
                "{name}: the header bytes on disk must be untouched by open"
            );
            assert_ne!(
                &after[HEADER_SIZE..],
                &before[HEADER_SIZE..],
                "{name}: payload must differ on disk after open"
            );
            assert_eq!(
                after.len(),
                before.len(),
                "{name}: in-place payload overwrite must not change the file length"
            );

            let _ = fs::remove_file(&decay_file);
        }

        let _ = fs::remove_file(&text_source);
        let _ = fs::remove_file(&audio_source);
    }

    #[test]
    fn audio_round_trip_preserves_spec_and_payload_length() {
        // The encoded payload must be exactly the source PCM, and the header must
        // carry back the sample rate and channel count needed to play it.
        let input = unique_temp_path("source.wav");
        let decay_file = unique_temp_path("clip.adcy3");
        fs::write(&input, wav_bytes(44_100, 2, 1_000)).expect("write test wav");
        encode_file(&input, &decay_file).expect("encode audio should succeed");

        let encoded = fs::read(&decay_file).expect("read encoded file");
        let header = Header::read(&encoded).expect("audio header must parse");
        let spec = header.audio_spec().expect("audio header must carry a spec");
        assert_eq!(spec.sample_rate, 44_100);
        assert_eq!(spec.channels, 2);
        assert_eq!(spec.bits_per_sample, AUDIO_BITS_PER_SAMPLE);
        assert_eq!(
            encoded.len() - HEADER_SIZE,
            1_000 * 2 * AUDIO_BYTES_PER_SAMPLE,
            "payload must be exactly the decoded PCM, every frame of it"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&decay_file);
    }

    #[test]
    fn sweeping_removes_stale_view_files() {
        // A display file from a previous open is a copy of a less corrupted state, so
        // the sweep must remove it. The current open's own file cannot be swept, since
        // the viewer is launched asynchronously and needs it to outlive the process.
        let stale = std::env::temp_dir().join(format!(
            "decayfmt_view_{}.txt",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_nanos()
        ));
        fs::write(&stale, b"a less corrupted state").expect("write stale view file");
        assert!(stale.exists(), "the stale file must exist before the sweep");

        sweep_stale_view_files();

        assert!(
            !stale.exists(),
            "the sweep must remove view files left by earlier opens"
        );
    }

    #[test]
    fn concurrent_opens_each_cost_a_corruption() {
        // Opening always costs a corruption, including when opens overlap. Corruption
        // only ever replaces bytes, so from an all-'a' payload the count of surviving
        // 'a' bytes falls with every open that lands. Without the exclusive lock two
        // opens could read the same starting payload and the later write would discard
        // the earlier one, leaving more survivors on disk than N sequential opens.
        use std::sync::Barrier;

        const THREADS: usize = 4;
        const PAYLOAD: usize = 4 * 1024 * 1024;

        let input = unique_temp_path("source.txt");
        let decay_file = unique_temp_path("note.tdcy10");
        fs::write(&input, vec![b'a'; PAYLOAD]).expect("write test source");
        encode_file(&input, &decay_file).expect("encode should succeed");

        let barrier = Barrier::new(THREADS);
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let path = decay_file.clone();
                let barrier = &barrier;
                scope.spawn(move || {
                    // Release every thread at once so the read-modify-write windows
                    // genuinely overlap.
                    barrier.wait();
                    decay_in_place(&path).expect("decay should succeed");
                });
            }
        });

        let on_disk = fs::read(&decay_file).expect("read opened file");
        let survivors = on_disk[HEADER_SIZE..]
            .iter()
            .filter(|&&b| b == b'a')
            .count();

        // At x=10 each open replaces about 63% of bytes, so after THREADS opens the
        // expected survival is 0.37^THREADS, about 1.9% here. Even one lost open would
        // leave roughly 0.37^(THREADS-1), about 5%, so this bound separates them
        // comfortably while staying far from the fully sequential expectation.
        let survival = survivors as f64 / (PAYLOAD as f64);
        assert!(
            survival < 0.035,
            "{survivors} of {PAYLOAD} bytes survived ({survival:.4});              an open was lost to a concurrent write"
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
}
