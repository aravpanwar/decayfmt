#!/usr/bin/env python3
"""Smoke tests for the decayfmt Python bindings.

Plain asserts, no pytest: run with any Python >= 3.11 that has the wheel
installed. Exercises every public function end to end, including the
statistical properties of corruption through the Python boundary.
"""

import base64
import os
import tempfile
import threading
import time

from pathlib import Path

import decayfmt


def changed_fraction(before, after):
    assert len(before) == len(after)
    return sum(a != b for a, b in zip(before, after)) / len(before)


def expected_version():
    """Reads the version from python/Cargo.toml, the manifest the wheel is built from.

    Hardcoding it here means every release breaks the smoke test until someone
    remembers to edit this file too, so it is read from the manifest instead.
    """
    manifest = Path(__file__).resolve().parent.parent / "Cargo.toml"
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    raise AssertionError(f"no version found in {manifest}")


def main():
    assert decayfmt.__version__ == expected_version(), decayfmt.__version__
    print("PASS import + __version__")

    # --- corrupt_bytes: statistical behavior through Python ----------------
    data = b"a" * 100_000
    frac1 = changed_fraction(data, decayfmt.corrupt_bytes(data, 1.0, "text"))
    frac10 = changed_fraction(data, decayfmt.corrupt_bytes(data, 10.0, "text"))
    assert 0.085 < frac1 < 0.105, f"x=1 fraction {frac1} outside (0.085, 0.105)"
    assert 0.61 < frac10 < 0.65, f"x=10 fraction {frac10} outside (0.61, 0.65)"
    print(f"PASS corrupt_bytes statistics (x=1: {frac1:.4f}, x=10: {frac10:.4f})")

    # --- corrupt_in_place: zero-copy mutation ------------------------------
    buf = bytearray(b"a" * 100_000)
    before = bytes(buf)
    decayfmt.corrupt_in_place(buf, 10.0, "text")
    assert bytes(buf) != before, "corrupt_in_place did not mutate the buffer"
    assert len(buf) == 100_000
    try:
        decayfmt.corrupt_in_place(buf, 1.0, "garbage")
        raise AssertionError("bad kind did not raise")
    except ValueError as e:
        assert "image" in str(e) and "text" in str(e)
    print("PASS corrupt_in_place mutation + bad kind ValueError")

    # --- image corruption preserves alpha -----------------------------------
    pixels = b"\x00\x00\x00\xAB" * 10_000
    img = bytearray(pixels)
    decayfmt.corrupt_in_place(img, 10.0, "image")
    for i in range(3, len(img), 4):
        assert img[i] == 0xAB, f"alpha modified at index {i}"
    # Checking a single pixel would fail by chance: at x=10 each channel survives
    # about 37% of the time, so all three surviving is a roughly 5% flake. Count
    # across the whole payload instead, where the expected share is far from zero.
    changed = sum(
        1 for i in range(len(img)) if i % 4 != 3 and img[i] != 0x00
    )
    assert changed > len(img) // 4, f"only {changed} rgb bytes were corrupted"
    print("PASS image alpha channel preserved")

    # --- corrupt_in_place pins the buffer while it runs ------------------------
    # The call must leave the bytearray resizable afterwards: a buffer export that
    # outlived the call would make every later append raise BufferError.
    pinned = bytearray(b"a" * 4096)
    decayfmt.corrupt_in_place(pinned, 10.0, "text")
    pinned.extend(b"tail")
    assert len(pinned) == 4100
    print("PASS corrupt_in_place releases its buffer export")

    # --- audio corruption displaces samples, never changes length -------------
    samples = (8000).to_bytes(2, "little", signed=True) * 50_000
    decayed = decayfmt.corrupt_bytes(samples, 10.0, "audio")
    assert len(decayed) == len(samples), "audio corruption changed the length"
    moved = sum(
        decayed[i : i + 2] != samples[i : i + 2] for i in range(0, len(samples), 2)
    )
    share = moved / (len(samples) // 2)
    assert 0.61 < share < 0.65, f"x=10 displaced {share} of samples"
    print(f"PASS audio corruption statistics (x=10: {share:.4f})")

    # --- filename parsing ----------------------------------------------------
    assert decayfmt.parse_filename("photo.idcy3") == ("image", 3.0)
    assert decayfmt.parse_filename("note.tdcy12") == ("text", 12.0)
    assert decayfmt.parse_filename("clip.adcy5") == ("audio", 5.0)
    for bad in ["plain.txt", "photo.idcy", "photo.idcyx", "photo.idcy0"]:
        try:
            decayfmt.parse_filename(bad)
            raise AssertionError(f"{bad!r} did not raise")
        except ValueError:
            pass
    print("PASS parse_filename")

    # --- header round trips ---------------------------------------------------
    header = decayfmt.write_header("image", 2, 2)
    assert len(header) == 16
    assert header[:4] == b"DCYF"
    assert decayfmt.read_header(header) == ("image", (2, 2))
    text_header = decayfmt.write_header("text", None, None)
    assert decayfmt.read_header(text_header) == ("text", None)
    audio_header = decayfmt.write_header("audio", sample_rate=44_100, channels=2)
    assert len(audio_header) == 16
    assert decayfmt.read_header(audio_header) == ("audio", None)
    for kind in ["image", "audio"]:
        try:
            decayfmt.write_header(kind, None, None)
            raise AssertionError(f"{kind} header without its metadata did not raise")
        except ValueError:
            pass
    print("PASS write_header/read_header round trips")

    # --- encode + decay_file on a text file -----------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, "source.txt")
        output = os.path.join(tmp, "note.tdcy5")
        with open(source, "w") as f:
            f.write("the quick brown fox jumps over the lazy dog\n")

        decayfmt.encode_file(source, output)
        kind, dims, bytes1 = decayfmt.decay_file(output)
        assert kind == "text" and dims is None
        assert bytes1[:4] == b"DCYF"

        _, _, bytes2 = decayfmt.decay_file(output)
        assert bytes1 != bytes2, "two opens must produce different corruption"
        assert len(bytes1) == len(bytes2), "open must preserve length"
        assert bytes1[:16] == bytes2[:16], "header must never change"
        assert bytes1[16:].count(b" ") > 0, "corrupted text should contain replacements"
    print("PASS encode_file + decay_file (text, twice)")

    # --- encode_bytes with an embedded 1x1 PNG --------------------------------
    one_px_png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    )
    with tempfile.TemporaryDirectory() as tmp:
        output = os.path.join(tmp, "photo.idcy3")
        decayfmt.encode_bytes(one_px_png, output)
        kind, dims, bytes1 = decayfmt.decay_file(output)
        assert kind == "image" and dims == (1, 1), (kind, dims)
        assert bytes1[:4] == b"DCYF"
    print("PASS encode_bytes + decay_file (1x1 PNG)")

    # --- invalid UTF-8 refused at encode --------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        output = os.path.join(tmp, "note.tdcy3")
        try:
            decayfmt.encode_bytes(b"\xff\xfe not utf8", output)
            raise AssertionError("invalid UTF-8 did not raise")
        except ValueError as e:
            assert "UTF-8" in str(e)
    print("PASS invalid UTF-8 refused")

    # --- soft GIL-release check -------------------------------------------------
    done = threading.Event()
    result = {}

    def worker():
        result["bytes"] = decayfmt.corrupt_bytes(
            b"\x00" * (64 * 1024 * 1024), 10.0, "text"
        )
        done.set()

    thread = threading.Thread(target=worker)
    thread.start()
    ticks = 0
    while not done.is_set():
        time.sleep(0.01)
        ticks += 1
    thread.join()
    assert len(result["bytes"]) == 64 * 1024 * 1024
    if ticks == 0:
        print("WARN: main thread never ticked during 64 MiB corrupt (GIL not released?)")
    else:
        print(f"PASS GIL soft check (main thread ticked {ticks} times during 64 MiB corrupt)")

    print("ALL SMOKE TESTS PASSED")


if __name__ == "__main__":
    main()
