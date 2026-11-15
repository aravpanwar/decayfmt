//! Python bindings for decayfmt, the file format where decay is a first-class
//! property: every open permanently corrupts the file.
//!
//! This module wraps the Rust library crate directly, the same corruption,
//! encode, and header routines the CLI uses, and exposes them as plain
//! functions. Errors map to built-in Python exceptions: filesystem failures
//! raise `OSError`, a read-only target raises `PermissionError`, and every
//! other refusal (bad magic, bad filename, invalid UTF-8, ...) raises
//! `ValueError`, each carrying the exact message the CLI would print.

use decayfmt_core::error::DecayError;
use decayfmt_core::format::{FileType, Header, AUDIO_BITS_PER_SAMPLE};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyOSError, PyPermissionError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyBytesMethods};
use std::path::Path;

/// Maps a `DecayError` to the built-in Python exception that best matches it.
///
/// `Io` becomes `OSError` (the message already includes the OS error string),
/// `ReadOnly` becomes `PermissionError`, and everything else becomes
/// `ValueError`. Messages are the exact `Display` text the CLI prints.
fn map_err(error: DecayError) -> PyErr {
    match &error {
        DecayError::Io { .. } => PyOSError::new_err(error.to_string()),
        DecayError::ReadOnly { .. } => PyPermissionError::new_err(error.to_string()),
        _ => PyValueError::new_err(error.to_string()),
    }
}

/// Parses a kind argument into a `FileType`, rejecting anything else.
fn file_type_from_str(kind: &str) -> PyResult<FileType> {
    match kind {
        "image" => Ok(FileType::Image),
        "text" => Ok(FileType::Text),
        "audio" => Ok(FileType::Audio),
        other => Err(PyValueError::new_err(format!(
            "kind must be \"image\", \"text\", or \"audio\", got {other:?}"
        ))),
    }
}

/// Corrupts a copy of `data` and returns the corrupted bytes.
///
/// Each eligible byte is independently replaced with probability
/// `1 - exp(-x / 10)`; image payloads corrupt R, G, and B channels only and
/// never touch alpha, text payloads are replaced with printable ASCII, and audio
/// payloads displace whole 16-bit samples by an amount bounded by `x`. `x` is
/// not clamped: `x <= 0` corrupts nothing, and larger `x` approaches corrupting
/// every byte. Because Python bytes are immutable, the input is copied once;
/// use `corrupt_in_place` on a `bytearray` to avoid the copy.
///
/// The GIL is released while corruption runs, and large payloads are processed
/// in parallel across cores.
#[pyfunction]
fn corrupt_bytes(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    x: f64,
    kind: &str,
) -> PyResult<Py<PyBytes>> {
    let file_type = file_type_from_str(kind)?;
    let mut bytes = data.as_bytes().to_vec();
    py.detach(|| decayfmt_core::corrupt::corrupt(&mut bytes, file_type, x));
    Ok(PyBytes::new(py, &bytes).into())
}

/// Corrupts a `bytearray` in place, with no copy.
///
/// Same statistics as `corrupt_bytes`, but mutates the given buffer directly.
/// Pass a `memoryview` by first converting it with `bytearray(mv)`. The GIL is
/// released while corruption runs; resizing the bytearray from another thread
/// during the call raises `BufferError` in that thread.
#[pyfunction]
fn corrupt_in_place(
    py: Python<'_>,
    buffer: &Bound<'_, PyByteArray>,
    x: f64,
    kind: &str,
) -> PyResult<()> {
    let file_type = file_type_from_str(kind)?;
    // The bytes are reached through a buffer export rather than a bare slice of the
    // bytearray. While an export is alive Python refuses to resize the bytearray, so
    // another thread that appends to or clears it during the detach below gets a
    // BufferError instead of freeing the storage this slice points into. A bare slice
    // would dangle in that case, because the GIL is not held while corruption runs.
    let view = PyBuffer::<u8>::get(buffer.as_any())?;
    let mut pointer = view
        .as_slice_ptr()
        .ok_or_else(|| PyValueError::new_err("expected a contiguous buffer"))?;
    // SAFETY: `view` outlives the slice and pins the allocation at this address and
    // length for as long as it is held. Another Python thread can still write to the
    // same bytes while the GIL is released; that is a race on the contents only, as
    // it is for any extension that releases the GIL over a buffer, never on the
    // allocation itself.
    let bytes = unsafe { pointer.as_mut() };
    py.detach(|| decayfmt_core::corrupt::corrupt(bytes, file_type, x));
    drop(view);
    Ok(())
}

/// Encodes a source file into a decayfmt file, exactly like the CLI `encode`.
///
/// The output name determines the payload type and x: `name.idcy<x>` for
/// images, `name.tdcy<x>` for text, `name.adcy<x>` for audio. The produced file
/// is clean; corruption happens at open time.
#[pyfunction]
fn encode_file(py: Python<'_>, source_path: &str, output_path: &str) -> PyResult<()> {
    let source = Path::new(source_path);
    let output = Path::new(output_path);
    py.detach(|| decayfmt_core::encode::encode_file(source, output))
        .map_err(map_err)
}

/// Encodes in-memory bytes into a decayfmt file.
///
/// The bytes are treated as a source file: decoded to raw RGBA for image
/// output names, validated as UTF-8 for text names, and decoded to raw PCM for
/// audio names. Useful for sources that are already in memory (e.g. an image
/// from PIL), or when `encode_file` would require a temporary file.
#[pyfunction]
fn encode_bytes(py: Python<'_>, source: &Bound<'_, PyBytes>, output_path: &str) -> PyResult<()> {
    let bytes = source.as_bytes().to_vec();
    let output = Path::new(output_path);
    py.detach(|| decayfmt_core::encode::encode_bytes(&bytes, output))
        .map_err(map_err)
}

/// Opens a decayfmt file: permanently corrupts it on disk, no display.
///
/// This is the CLI's open minus the display step: the corrupted payload is
/// written back to the file before returning. Returns the file type label, the
/// image dimensions (`None` for text and audio), and the full new file bytes
/// including the untouched header.
#[pyfunction]
#[allow(clippy::type_complexity)]
fn decay_file(py: Python<'_>, path: &str) -> PyResult<(String, Option<(u32, u32)>, Py<PyBytes>)> {
    let path = Path::new(path);
    let (header, file_bytes) = py
        .detach(|| decayfmt_core::open::decay_in_place(path))
        .map_err(map_err)?;
    let kind = header.file_type.label().to_string();
    let dimensions = header.image_dimensions().map(|d| (d.width, d.height));
    let bytes = PyBytes::new(py, &file_bytes).into();
    Ok((kind, dimensions, bytes))
}

/// Parses a decayfmt filename into its payload type label and instability x.
///
/// `photo.idcy3` parses as `("image", 3.0)` and `note.tdcy12` as
/// `("text", 12.0)`. Raises `ValueError` for names that do not fit the
/// convention.
#[pyfunction]
fn parse_filename(name: &str) -> PyResult<(String, f64)> {
    let (file_type, x) = decayfmt_core::format::parse_filename(Path::new(name)).map_err(map_err)?;
    Ok((file_type.label().to_string(), x))
}

/// Reads the 16-byte decayfmt header from `data` and returns its type label
/// and image dimensions (`None` for text and audio).
#[pyfunction]
fn read_header(data: &Bound<'_, PyBytes>) -> PyResult<(String, Option<(u32, u32)>)> {
    let header = Header::read(data.as_bytes()).map_err(map_err)?;
    Ok((
        header.file_type.label().to_string(),
        header.image_dimensions().map(|d| (d.width, d.height)),
    ))
}

/// Builds a 16-byte decayfmt header.
///
/// `kind="image"` requires both `width` and `height`; `kind="audio"` requires
/// `sample_rate` and `channels`; `kind="text"` ignores them all. Useful together
/// with `encode_bytes`-style workflows that write their own files.
#[pyfunction]
#[pyo3(signature = (kind, width=None, height=None, sample_rate=None, channels=None))]
fn write_header(
    py: Python<'_>,
    kind: &str,
    width: Option<u32>,
    height: Option<u32>,
    sample_rate: Option<u32>,
    channels: Option<u8>,
) -> PyResult<Py<PyBytes>> {
    let file_type = file_type_from_str(kind)?;
    let header = match file_type {
        FileType::Image => match (width, height) {
            (Some(width), Some(height)) => Header::for_image(width, height),
            _ => {
                return Err(PyValueError::new_err(
                    "image headers require both width and height",
                ));
            }
        },
        FileType::Text => Header::for_text(),
        FileType::Audio => match (sample_rate, channels) {
            (Some(sample_rate), Some(channels)) => {
                Header::for_audio(sample_rate, channels, AUDIO_BITS_PER_SAMPLE)
            }
            _ => {
                return Err(PyValueError::new_err(
                    "audio headers require both sample_rate and channels",
                ));
            }
        },
    };
    Ok(PyBytes::new(py, &header.write()).into())
}

/// Python bindings for decayfmt.
#[pymodule]
fn decayfmt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(corrupt_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(corrupt_in_place, m)?)?;
    m.add_function(wrap_pyfunction!(encode_file, m)?)?;
    m.add_function(wrap_pyfunction!(encode_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(decay_file, m)?)?;
    m.add_function(wrap_pyfunction!(parse_filename, m)?)?;
    m.add_function(wrap_pyfunction!(read_header, m)?)?;
    m.add_function(wrap_pyfunction!(write_header, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
