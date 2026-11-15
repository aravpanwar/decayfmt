//! Encode a source file into a decayfmt file.
//!
//! This module reads a source image, text, or audio file, builds the fixed header via
//! format.rs, and writes the header followed by the raw, uncorrupted payload. The
//! invariant it upholds is that encoding never corrupts: a freshly encoded file is
//! clean. Corruption only ever happens at open time, in open.rs. All file I/O for
//! the encode flow lives here.

use crate::error::DecayError;
use crate::format::{FileType, Header, AUDIO_BITS_PER_SAMPLE};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Stands in for the source path in error messages when the source is a byte buffer
/// rather than a file.
const IN_MEMORY_SOURCE: &str = "<in-memory bytes>";

/// Decodes a source image's bytes into its pixel dimensions and a raw RGBA payload.
///
/// The image crate accepts any format it supports (PNG, JPEG, and others) and is
/// reduced here to raw RGBA, four bytes per pixel, which is exactly what the
/// decayfmt payload stores. The dimensions are returned alongside so the header can
/// record them; the payload is the pixel data only and does not encode its own size.
pub fn decode_image(source_bytes: &[u8], input: &Path) -> Result<(u32, u32, Vec<u8>), DecayError> {
    let decoded =
        image::load_from_memory(source_bytes).map_err(|error| DecayError::ImageDecode {
            context: format!("encode: decode image '{}': {}", input.display(), error),
        })?;
    let rgba = decoded.to_rgba8();
    let (width, height) = rgba.dimensions();
    Ok((width, height, rgba.into_raw()))
}

/// Decodes a source audio file into its playback parameters and a raw PCM payload.
///
/// symphonia probes the container (WAV, FLAC, MP3, OGG) and decodes the first audio
/// track to interleaved signed 16-bit little-endian samples, which is what the decayfmt
/// payload stores. This mirrors how images are reduced to raw RGBA: the container is
/// stripped so corruption operates on samples rather than on compressed frames, where
/// damaging a single byte would break the codec instead of degrading the sound.
///
/// The sample rate and channel count are returned alongside so the header can record
/// them; the payload is sample data only and does not describe itself.
pub fn decode_audio(source_bytes: &[u8], input: &Path) -> Result<(u32, u8, Vec<u8>), DecayError> {
    use symphonia::core::codecs::audio::AudioDecoderOptions;
    use symphonia::core::formats::probe::Hint;
    use symphonia::core::formats::FormatOptions;
    use symphonia::core::io::MediaSourceStream;
    use symphonia::core::meta::MetadataOptions;

    let decode_error = |message: String| DecayError::AudioDecode {
        context: format!("encode: decode audio '{}': {}", input.display(), message),
    };

    // symphonia reads from a seekable stream; the source is already in memory.
    let stream = MediaSourceStream::new(
        Box::new(std::io::Cursor::new(source_bytes.to_vec())),
        Default::default(),
    );

    // The extension is a hint only. If it is wrong or absent, symphonia still probes
    // the container by its magic bytes.
    let mut hint = Hint::new();
    if let Some(extension) = input.extension().and_then(|raw| raw.to_str()) {
        hint.with_extension(extension);
    }

    let mut format = symphonia::default::get_probe()
        .probe(
            &hint,
            stream,
            FormatOptions::default(),
            MetadataOptions::default(),
        )
        .map_err(|error| decode_error(error.to_string()))?;

    let track = format
        .default_track(symphonia::core::formats::TrackType::Audio)
        .ok_or_else(|| decode_error("no audio track found".to_string()))?;
    let track_id = track.id;
    let codec_params = track
        .codec_params
        .as_ref()
        .and_then(|params| params.audio())
        .ok_or_else(|| decode_error("track has no audio parameters".to_string()))?;

    let mut decoder = symphonia::default::get_codecs()
        .make_audio_decoder(codec_params, &AudioDecoderOptions::default())
        .map_err(|error| decode_error(error.to_string()))?;

    let mut sample_rate = codec_params.sample_rate.unwrap_or(0);
    let mut channels = codec_params
        .channels
        .as_ref()
        .map(|channels| channels.count())
        .unwrap_or(0);
    let mut payload: Vec<u8> = Vec::new();
    // copy_bytes_to_vec_interleaved_as resizes its destination to exactly the packet it
    // is given, so each packet is converted into this scratch buffer and then appended.
    // Writing straight into the payload would overwrite the packets already decoded.
    let mut packet_bytes: Vec<u8> = Vec::new();

    // Decode every packet of the chosen track, interleaving samples as they arrive.
    // An unsupported or corrupt packet ends decoding rather than being skipped, so a
    // truncated clip is never silently encoded as if it were whole.
    while let Some(packet) = format
        .next_packet()
        .map_err(|error| decode_error(error.to_string()))?
    {
        if packet.track_id != track_id {
            continue;
        }
        let decoded = decoder
            .decode(&packet)
            .map_err(|error| decode_error(error.to_string()))?;

        let spec = decoded.spec();
        if sample_rate == 0 {
            sample_rate = spec.rate();
        }
        if channels == 0 {
            channels = spec.channels().count();
        }

        // Append this packet's frames as interleaved signed 16-bit little-endian bytes,
        // converting from whatever sample format the codec produced.
        decoded.copy_bytes_to_vec_interleaved_as::<i16>(&mut packet_bytes);
        payload.extend_from_slice(&packet_bytes);
    }

    if sample_rate == 0 || channels == 0 {
        return Err(decode_error(
            "missing sample rate or channel count".to_string(),
        ));
    }
    if payload.is_empty() {
        return Err(decode_error("no audio samples decoded".to_string()));
    }
    let channels = u8::try_from(channels).map_err(|_| {
        decode_error(format!(
            "{channels} channels exceeds the 255 the header holds"
        ))
    })?;

    Ok((sample_rate, channels, payload))
}

/// Produces a raw text payload from source bytes, requiring valid UTF-8.
///
/// The payload is stored as raw UTF-8 bytes exactly as read. Invalid UTF-8 is
/// refused at encode time so that only well-formed text ever enters the format;
/// the later corruption at open time is what may break that validity.
pub fn text_payload(source_bytes: Vec<u8>) -> Result<Vec<u8>, DecayError> {
    match std::str::from_utf8(&source_bytes) {
        Ok(_) => Ok(source_bytes),
        Err(_) => Err(DecayError::InvalidUtf8),
    }
}

/// Writes the header and raw payload to the output path as a single file.
///
/// The header is written exactly once, here, and is never rewritten afterward.
/// The payload follows immediately after the fixed 16-byte header. The two are
/// written with two calls so the payload is never copied into a second full-size
/// buffer; the bytes on disk are identical to writing one concatenated buffer.
pub fn write_decayfmt(output: &Path, header: Header, payload: &[u8]) -> Result<(), DecayError> {
    let write_error = |error| DecayError::Io {
        context: format!("encode: write output '{}'", output.display()),
        source: error,
    };
    let mut file = fs::File::create(output).map_err(write_error)?;
    file.write_all(&header.write()).map_err(write_error)?;
    file.write_all(payload).map_err(write_error)
}

/// Encodes a source file at `input` into a decayfmt file at `output`.
///
/// The payload type and the instability value x both come from the output filename
/// (`name.idcy<x>`, `name.tdcy<x>`, or `name.adcy<x>`), parsed by the same routine
/// open uses, so an output name that could never be opened, a missing or malformed x,
/// is refused here rather than producing a permanently unopenable file. The source is
/// read and turned into a raw payload (RGBA for images, UTF-8 for text, 16-bit PCM for
/// audio), and the header plus payload are written out. No corruption is applied; the produced file is clean and parses
/// cleanly via format.rs. The value of x is not stored; it lives only in the filename.
pub fn encode_file(input: &Path, output: &Path) -> Result<(), DecayError> {
    // Parse the output name first, before any read: an output name that could
    // never be opened is refused rather than producing a permanently unopenable
    // file.
    let (file_type, _x) = crate::format::parse_filename(output)?;

    let source_bytes = fs::read(input).map_err(|error| DecayError::Io {
        context: format!("encode: read input '{}'", input.display()),
        source: error,
    })?;

    build_and_write(file_type, source_bytes, input, output)
}

/// Encodes in-memory source bytes into a decayfmt file at `output`.
///
/// The bytes are treated as a source file: decoded to raw RGBA for images, validated
/// as UTF-8 for text, and decoded to raw PCM for audio, exactly as `encode_file`
/// treats a file on disk. The payload type and x come from the output filename, as
/// always.
pub fn encode_bytes(source: &[u8], output: &Path) -> Result<(), DecayError> {
    let (file_type, _x) = crate::format::parse_filename(output)?;
    // There is no source path to report, and naming the output instead would blame a
    // decode failure on a file that was never read.
    build_and_write(
        file_type,
        source.to_vec(),
        Path::new(IN_MEMORY_SOURCE),
        output,
    )
}

/// Turns already-read source bytes into a header and payload and writes them out.
///
/// `source_path` names the source only for error message context; the bytes have
/// already been read by the caller.
fn build_and_write(
    file_type: FileType,
    source_bytes: Vec<u8>,
    source_path: &Path,
    output: &Path,
) -> Result<(), DecayError> {
    let (header, payload) = match file_type {
        FileType::Image => {
            let (width, height, payload) = decode_image(&source_bytes, source_path)?;
            (Header::for_image(width, height), payload)
        }
        FileType::Text => (Header::for_text(), text_payload(source_bytes)?),
        FileType::Audio => {
            let (sample_rate, channels, payload) = decode_audio(&source_bytes, source_path)?;
            (
                Header::for_audio(sample_rate, channels, AUDIO_BITS_PER_SAMPLE),
                payload,
            )
        }
    };

    write_decayfmt(output, header, &payload)
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
        std::env::temp_dir().join(format!("decayfmt_test_{}_{}", nanos, suffix))
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
            header.image_dimensions(),
            Some(ImageDimensions { width, height }),
            "header must record the source image dimensions"
        );

        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
    }
}
