# decayfmt-py

A file format where decay is a first-class property: **every open permanently corrupts the file.**

This is the Python binding for the [decayfmt](https://github.com/aravpanwar/decayfmt) format. Install it with `pip install decayfmt-py`; the module you import is `decayfmt`. Encode a clean file once, then let it decay one open at a time. Each open replaces a random slice of the payload with noise and writes it back to disk. A corrupted file cannot be restored from its own contents. The header is immutable; only the payload decays.

The binding wraps the same Rust library the CLI uses, so behavior, statistics, and errors are identical.

## Install

```bash
pip install decayfmt-py
```

Requires Python 3.11+. Wheels are built from Rust via PyO3 (abi3), so no Rust toolchain is needed at install time.

## Quickstart

```python
import decayfmt

# Encode a clean text file. The extension carries the type and the decay rate:
# `tdcy<x>` = text, `idcy<x>` = image, `adcy<x>` = audio, x = instability
# (higher decays faster).
decayfmt.encode_file("notes.txt", "notes.tdcy5")

# Open it five times. Each open permanently corrupts the file on disk.
for _ in range(5):
    kind, dims, data = decayfmt.decay_file("notes.tdcy5")
    print(data[16:].decode("utf-8", errors="replace"))

# Work purely in memory instead: each call decays a fresh copy of the bytes.
data = b"the quick brown fox jumps over the lazy dog"
for _ in range(8):
    data = decayfmt.corrupt_bytes(data, 1.0, "text")
print(data.decode("utf-8", errors="replace"))

# Zero-copy decay of a mutable buffer:
buf = bytearray(b"some text that will decay")
decayfmt.corrupt_in_place(buf, 10.0, "text")
```

Corruption probability per eligible byte is `p = 1 - exp(-x / 10)`: x = 1 corrupts roughly 9.5% per open, x = 10 roughly 63%. Image corruption touches only the R, G, and B channels, so transparency (alpha) is never damaged. Text corruption replaces bytes with printable ASCII, so at high x it can break UTF-8 sequences. Audio corruption displaces whole 16-bit samples by an amount bounded by x, so a clip keeps its length however far it decays.

## API

| Function | Returns | Notes |
| --- | --- | --- |
| `corrupt_bytes(data, x, kind) -> bytes` | corrupted copy | `kind` is `"image"`, `"text"`, or `"audio"`; immutable bytes are copied once |
| `corrupt_in_place(buffer, x, kind) -> None` | nothing | mutates a `bytearray` in place, no copy; for a `memoryview` use `bytearray(mv)` |
| `encode_file(source_path, output_path) -> None` | nothing | same as the CLI `encode`; output name decides type and x |
| `encode_bytes(source, output_path) -> None` | nothing | encodes in-memory bytes (image and audio formats decoded, text validated as UTF-8) |
| `decay_file(path) -> (kind, dims, bytes)` | type label, `(w, h)` or `None`, full file bytes | **permanently corrupts the file on disk**, no display |
| `parse_filename(name) -> (kind, x)` | type label, x | `"photo.idcy3"` → `("image", 3.0)` |
| `read_header(data) -> (kind, dims)` | type label, `(w, h)` or `None` | reads the 16-byte header |
| `write_header(kind, width=None, height=None, sample_rate=None, channels=None) -> bytes` | 16-byte header | image requires `width` and `height`; audio requires `sample_rate` and `channels` |
| `decayfmt.__version__` | version string | matches the installed package version |

`x` is not clamped: `x <= 0` corrupts nothing, and large `x` approaches corrupting every byte. The CLI reads x from filenames as a positive integer; the API accepts any float.

## Errors

Failures raise built-in exceptions with the exact message the CLI would print:

- `OSError` for filesystem read/write failures (includes the OS error string).
- `PermissionError` for a read-only target, where the corrupted payload cannot be written back.
- `ValueError` for everything else: wrong magic bytes, unknown version, bad filename convention, invalid UTF-8 at encode, undecodable image or audio, and so on.

## Threading

The GIL is released while corruption, encoding, and file operations run, and large payloads (≥ 1 MiB) are corrupted in parallel across cores. Corruption is drawn from generators seeded by operating system entropy, so the corruption sequence cannot be replayed.

`corrupt_in_place` holds a buffer export on the `bytearray` for the duration of the call, so resizing it from another thread meanwhile raises `BufferError` in that thread.

## Image formats

`encode_file` / `encode_bytes` accept whatever the underlying Rust image library decodes: PNG, JPEG, GIF, WebP, TIFF, QOI, BMP, DDS, EXR, HDR, ICO, PNM, TGA, and farbfeld. Images are stored as raw RGBA, so any format the library can decode becomes a decaying image.

## Audio formats

WAV, FLAC, MP3, and OGG Vorbis sources are decoded to raw interleaved signed 16-bit PCM, so an encoded audio file is much larger than a compressed source.

## License

MIT. Same license as the [decayfmt](https://github.com/aravpanwar/decayfmt) project.
