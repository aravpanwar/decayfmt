#!/usr/bin/env python3
"""Example: every decayfmt Python function, plus its exceptions.

Install first:

    pip install decayfmt-py

Then run this file from anywhere. It creates its files in a temporary
directory and cleans them up, so it is safe to run repeatedly.

Each section below shows one function. The exception section shows every
error type the bindings can raise and how to catch them.
"""

import base64
import shutil
import tempfile
from pathlib import Path

import decayfmt

print(f"decayfmt {decayfmt.__version__} loaded")
print()

tmp = Path(tempfile.mkdtemp(prefix="decayfmt_example_"))

# ---------------------------------------------------------------------------
# parse_filename: read type + instability x from a decayfmt name
# ---------------------------------------------------------------------------
kind, x = decayfmt.parse_filename("photo.idcy3")
print(f"parse_filename('photo.idcy3') -> kind={kind!r}, x={x}")
kind, x = decayfmt.parse_filename("note.tdcy12")
print(f"parse_filename('note.tdcy12') -> kind={kind!r}, x={x}")
print()

# ---------------------------------------------------------------------------
# corrupt_bytes: decay a copy of immutable bytes, returns new bytes
# ---------------------------------------------------------------------------
data = b"the quick brown fox jumps over the lazy dog"
original = data
for step in range(8):
    data = decayfmt.corrupt_bytes(data, 1.0, "text")
print("corrupt_bytes: 8 opens of the same bytes in memory")
print("  before:", original)
print("  after: ", data)
print()

# ---------------------------------------------------------------------------
# corrupt_in_place: same statistics, but mutates a bytearray with no copy
# ---------------------------------------------------------------------------
buf = bytearray(b"some text that will decay in place")
decayfmt.corrupt_in_place(buf, 10.0, "text")
print("corrupt_in_place: mutated in place, no copy")
print("  after: ", bytes(buf))
print()

# image corruption never touches the alpha channel (every 4th byte):
pixels = bytearray(b"\x00\x00\x00\xFF" * 100)
decayfmt.corrupt_in_place(pixels, 10.0, "image")
alphas = pixels[3::4]
assert all(a == 0xFF for a in alphas), "alpha must survive"
print("corrupt_in_place: image alpha channel preserved")
print()

# ---------------------------------------------------------------------------
# encode_file: source file on disk -> clean decayfmt file on disk
# ---------------------------------------------------------------------------
source = tmp / "notes.txt"
source.write_text("hello from the example file\n")
output = tmp / "notes.tdcy5"

decayfmt.encode_file(str(source), str(output))
print(f"encode_file: wrote clean decayfmt file to {output.name}")
print()

# ---------------------------------------------------------------------------
# decay_file: open without display; corrupts the file on disk
# ---------------------------------------------------------------------------
kind, dims, file_bytes = decayfmt.decay_file(str(output))
print(f"decay_file: kind={kind!r}, dims={dims}, first 16 bytes = header")
print("  corrupted text:", file_bytes[16:].decode("utf-8", errors="replace"))

kind, dims, file_bytes = decayfmt.decay_file(str(output))
print("  one more open:", file_bytes[16:].decode("utf-8", errors="replace"))
print()

# ---------------------------------------------------------------------------
# encode_bytes: encode bytes already in memory (no source file needed)
# ---------------------------------------------------------------------------
png = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)
photo_out = tmp / "photo.idcy3"
decayfmt.encode_bytes(png, str(photo_out))
kind, dims, _ = decayfmt.decay_file(str(photo_out))
print(f"encode_bytes: 1x1 PNG from memory -> kind={kind!r}, dims={dims}")
print()

# ---------------------------------------------------------------------------
# write_header / read_header: build and inspect the 16-byte header
# ---------------------------------------------------------------------------
header = decayfmt.write_header("image", 64, 48)
print("write_header: 16 bytes:", header.hex())
kind, dims = decayfmt.read_header(header)
print(f"read_header:   kind={kind!r}, dims={dims}")

text_header = decayfmt.write_header("text", None, None)
print(f"read_header:   {decayfmt.read_header(text_header)}")
print()

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
print("Exceptions:")


def show_exception(label, fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001 - demonstrating all error types
        print(f"  {label:<38} -> {type(e).__name__}: {e}")
    else:
        raise AssertionError(f"{label} did not raise!")


# ValueError: kind must be "image", "text", or "audio"
show_exception("corrupt_bytes(bad kind)", lambda: decayfmt.corrupt_bytes(b"x", 1.0, "video"))

# ValueError: filename does not fit the convention
show_exception("parse_filename('plain.txt')", lambda: decayfmt.parse_filename("plain.txt"))
show_exception("parse_filename('photo.idcy')", lambda: decayfmt.parse_filename("photo.idcy"))
show_exception("parse_filename('photo.idcy0')", lambda: decayfmt.parse_filename("photo.idcy0"))

# ValueError: image header requires dimensions
show_exception("write_header('image', None, None)", lambda: decayfmt.write_header("image", None, None))

# ValueError: text must be valid UTF-8 at encode time
bad_text = tmp / "bad.tdcy3"
show_exception(
    "encode_bytes(invalid UTF-8)",
    lambda: decayfmt.encode_bytes(b"\xff\xfe not utf8", str(bad_text)),
)

# ValueError: source cannot be decoded as an image
bad_png = tmp / "fake.idcy3"
show_exception(
    "encode_bytes(not an image)",
    lambda: decayfmt.encode_bytes(b"definitely not a png", str(bad_png)),
)

# ValueError: wrong magic bytes; the name fits, the contents are not a decayfmt file
not_decayfmt = tmp / "fake.tdcy3"
not_decayfmt.write_text("just a text file")
show_exception("decay_file(wrong magic)", lambda: decayfmt.decay_file(str(not_decayfmt)))

# ValueError: extension/header type mismatch (image file under a text name)
mismatched = tmp / "photo.tdcy3"
decayfmt.encode_bytes(png, str(photo_out))
Path(str(photo_out)).rename(mismatched)
show_exception("decay_file(type mismatch)", lambda: decayfmt.decay_file(str(mismatched)))

# OSError: filesystem failure; source does not exist
show_exception(
    "encode_file(missing source)",
    lambda: decayfmt.encode_file(str(tmp / "nope.txt"), str(tmp / "out.tdcy3")),
)

# PermissionError: read-only target is refused (corruption cannot be written back)
readonly = tmp / "locked.tdcy3"
decayfmt.encode_file(str(source), str(readonly))
readonly.chmod(0o444)
show_exception("decay_file(read-only target)", lambda: decayfmt.decay_file(str(readonly)))
readonly.chmod(0o644)
print()

print("All functions and exceptions demonstrated. Cleaning up.")
shutil.rmtree(tmp)
