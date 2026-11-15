//! Manual timing benchmark for end-to-end encode.
//!
//! Builds one 2048x2048 RGBA image (16 MiB raw payload) and one 16 MiB text
//! source, saves each once outside the timed region, then times
//! `encode::encode_file` repeatedly on the same pair of paths. Reports
//! wall-time per encode; the numbers bound what any client can achieve end to
//! end, since PNG decode and disk I/O dominate.
//!
//! Usage: `cargo bench --bench encode` (release profile by default).

use decayfmt::encode::encode_file;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MIN_SCENARIO_SECS: f64 = 1.5;
const IMAGE_SIDE: u32 = 2048;
const TEXT_MB: usize = 16;

/// Unique path in the system temp directory so concurrent runs do not collide.
fn unique_temp_path(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("decayfmt_bench_{}_{}", nanos, suffix))
}

fn bench(name: &str, input: &Path, output: &Path, payload_bytes: usize) {
    // Warmup: one untimed encode so caches and code paths are hot.
    encode_file(input, output).expect("warmup encode");

    let mut reps = 1u64;
    let (elapsed, count) = loop {
        let start = Instant::now();
        for _ in 0..reps {
            encode_file(input, output).expect("timed encode");
        }
        let elapsed = start.elapsed();
        if elapsed.as_secs_f64() >= MIN_SCENARIO_SECS {
            break (elapsed, reps);
        }
        reps *= 2;
    };

    let per_rep = elapsed.as_secs_f64() / count as f64;
    println!(
        "{:>5} encode: {:>8.1} ms/encode  ({:>6} reps in {:>6.2} s, {:.1} MiB source payload)",
        name,
        per_rep * 1000.0,
        count,
        elapsed.as_secs_f64(),
        payload_bytes as f64 / (1024.0 * 1024.0),
    );
}

fn main() {
    let image_input = unique_temp_path("source.png");
    let image_output = unique_temp_path("photo.idcy3");
    let text_input = unique_temp_path("source.txt");
    let text_output = unique_temp_path("note.tdcy3");

    // 2048x2048 RGBA = 16 MiB raw payload. Save the PNG once, outside timing.
    let image = image::RgbaImage::from_fn(IMAGE_SIDE, IMAGE_SIDE, |x, y| {
        image::Rgba([
            (x as u8).wrapping_mul(3),
            (y as u8).wrapping_mul(5),
            ((x ^ y) as u8).wrapping_mul(7),
            255,
        ])
    });
    image.save(&image_input).expect("save bench source png");
    let image_raw_bytes = (IMAGE_SIDE as usize) * (IMAGE_SIDE as usize) * 4;

    // 16 MiB of printable ASCII, no entropy cost, valid UTF-8.
    let text: Vec<u8> = (0..TEXT_MB * 1024 * 1024)
        .map(|i| b'a' + (i % 26) as u8)
        .collect();
    std::fs::write(&text_input, &text).expect("write bench source text");

    println!("encode benchmark: end to end (read + decode + build + write)");
    bench("image", &image_input, &image_output, image_raw_bytes);
    bench("text", &text_input, &text_output, text.len());

    let _ = std::fs::remove_file(&image_input);
    let _ = std::fs::remove_file(&image_output);
    let _ = std::fs::remove_file(&text_input);
    let _ = std::fs::remove_file(&text_output);
}
