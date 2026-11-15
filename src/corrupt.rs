//! Corruption algorithms for image, text, and audio payloads.
//!
//! These are pure functions over byte slices. There is no file I/O and no CLI
//! logic here; the caller is responsible for reading the payload, calling into
//! this module, and writing the result back. The invariant this module upholds is
//! that corruption is always stochastic and always drawn from a cryptographically
//! secure generator seeded from operating system entropy, never from a fixed seed,
//! so the corruption sequence is not reproducible. Large payloads are
//! processed in parallel regions, each of which seeds its own OS-entropy
//! generator; the per-byte decisions stay independent across region boundaries,
//! so the aggregate remains undirected noise.

// `chunks_exact_to_as_chunks` (a newer clippy lint) suggests `slice::as_chunks`, which is
// stable only from Rust 1.88; we keep `chunks_exact` to preserve a low minimum supported
// Rust version. `unknown_lints` is allowed too so older clippy versions that predate this
// lint do not warn about the allow itself.
#![allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]

use crate::format::{FileType, AUDIO_BYTES_PER_SAMPLE};
use rand::{Rng, RngCore};

/// The divisor in the corruption probability curve p = 1 - exp(-x / DECAY_SCALE).
///
/// It is the tuning constant that sets how a given x feels. Lowering it makes
/// every x more destructive (the curve rises toward p = 1 faster); raising it
/// makes every x gentler (more opens are needed to reach the same damage). At the
/// current value of 10, x = 1 corrupts roughly 9.5% of eligible bytes per open and
/// x = 10 corrupts roughly 63%. Changing this number changes the meaning of every
/// existing filename's x, so it is fixed rather than configurable.
const DECAY_SCALE: f64 = 10.0;

/// Number of bytes per pixel in an RGBA image payload.
const RGBA_BYTES_PER_PIXEL: usize = 4;

/// Index of the alpha channel within an RGBA pixel. This byte is never corrupted.
const ALPHA_INDEX: usize = 3;

/// Largest displacement applied to an audio sample at the most destructive x, as an
/// absolute sample value. Full scale, so as x rises the injected noise grows loud enough
/// to bury the payload rather than merely sitting alongside it. Raising it makes every
/// audio x harsher; lowering it makes audio decay gentler without touching text or
/// images.
const AUDIO_MAX_NOISE: u16 = 32_767;

/// Lowest printable ASCII byte used as a text corruption replacement (space).
const PRINTABLE_ASCII_LOW: u8 = 0x20;

/// Highest printable ASCII byte used as a text corruption replacement (tilde).
const PRINTABLE_ASCII_HIGH: u8 = 0x7E;

/// Number of printable ASCII bytes in the text replacement range.
const PRINTABLE_ASCII_COUNT: u16 = (PRINTABLE_ASCII_HIGH - PRINTABLE_ASCII_LOW) as u16 + 1;

/// Largest draw accepted for the cheap rejection-free text replacement mapping:
/// 689 full copies of 0..95 fit in [0, 65455), so a draw below this value maps to
/// a uniformly distributed replacement with no rejection. Draws at or above it
/// (0.124% of the range) fall back to a direct uniform draw.
const TEXT_REPLACEMENT_ACCEPT_MAX: u16 = PRINTABLE_ASCII_COUNT * 689;

/// Bytes of payload processed per pool fill. Two u16 draws per byte covers the
/// worst case (every byte corrupted), so one fill covers a chunk of this size.
const CHUNK_BYTES: usize = 64 * 1024;

/// Payload length below which the parallel path is not worth the coordination.
const PAR_MIN_BYTES: usize = 1024 * 1024;

/// Size of the contiguous region handed to each parallel task. Kept a multiple
/// of 4 so image regions start on pixel boundaries and alpha stays at index 3.
const REGION_BYTES: usize = 4 * 1024 * 1024;

/// Derives the per-byte corruption probability from the instability value x.
///
/// p = 1 - exp(-x / DECAY_SCALE). The exponential form makes p climb smoothly from
/// 0 toward 1 as x grows, without ever needing to clamp. x must be positive; the
/// caller is responsible for having validated that before reaching this module.
fn corruption_probability(x: f64) -> f64 {
    1.0 - (-x / DECAY_SCALE).exp()
}

/// Converts a probability to the 16-bit integer threshold used by the bulk
/// corruption loops.
///
/// A byte is corrupted when its random draw, uniform over [0, 65536), is below
/// the threshold, giving an effective per-byte probability of t / 65536. That
/// deviates from the continuous p by at most 1 / 65536 (about 1.5e-5), which is
/// far below what any filename x can distinguish. The cast saturates: p = 1
/// becomes 65535, so even a saturated threshold leaves roughly 1 byte in 65536
/// untouched.
fn probability_threshold(x: f64) -> u16 {
    (corruption_probability(x) * 65536.0) as u16
}

/// Corrupts a payload in place according to its file type and instability value x.
///
/// Mutates the slice directly. Randomness is drawn in bulk from `rand::thread_rng`
/// generators, cryptographically secure and seeded from operating system entropy;
/// large payloads are split into parallel regions that each seed their own
/// generator, so two opens of the same bytes produce different results. Upholds
/// the invariant that corruption is never driven by a fixed, replayable seed.
pub fn corrupt(payload: &mut [u8], file_type: FileType, x: f64) {
    let threshold = probability_threshold(x);
    corrupt_payload(payload, file_type, threshold);
}

/// Corrupts the eligible portion of `payload` using the given integer threshold.
///
/// Text and audio corrupt every byte; image corrupts only the R, G, and B channels
/// of whole pixels. Image and audio payloads are truncated to a whole number of
/// pixels or samples, so any trailing partial unit is left untouched.
fn corrupt_payload(payload: &mut [u8], file_type: FileType, threshold: u16) {
    let eligible_len = match file_type {
        FileType::Text => payload.len(),
        FileType::Image => payload.len() - payload.len() % RGBA_BYTES_PER_PIXEL,
        // Audio corrupts every byte of every whole sample. A trailing partial sample
        // is left alone so the payload always ends on a sample boundary.
        FileType::Audio => payload.len() - payload.len() % AUDIO_BYTES_PER_SAMPLE,
    };
    if eligible_len == 0 {
        return;
    }
    let eligible = &mut payload[..eligible_len];

    let parallel = eligible_len >= PAR_MIN_BYTES
        && std::thread::available_parallelism()
            .map(|cores| cores.get() > 1)
            .unwrap_or(false);

    if parallel {
        use rayon::prelude::*;
        // Disjoint contiguous regions, each a multiple of 4 so image pixels
        // never straddle a boundary. Every region seeds its own OS-entropy
        // generator, keeping per-byte decisions independent across boundaries.
        eligible.par_chunks_mut(REGION_BYTES).for_each(|region| {
            let mut rng = rand::thread_rng();
            region_work(region, file_type, threshold, &mut rng);
        });
    } else {
        let mut rng = rand::thread_rng();
        region_work(eligible, file_type, threshold, &mut rng);
    }
}

/// Corrupts a whole region sequentially, in sub-blocks of `CHUNK_BYTES`.
///
/// Per sub-block, one bulk fill of a u16 pool supplies all threshold and
/// replacement draws for that block, so per-byte distribution calls are replaced
/// by one stream fill plus integer compares. The pool is sized for the worst
/// case of two draws per byte and is reused across sub-blocks, keeping transient
/// memory bounded to the pool (256 KiB) per region.
fn region_work<R: RngCore>(
    mut region: &mut [u8],
    file_type: FileType,
    threshold: u16,
    rng: &mut R,
) {
    let mut pool = vec![0u16; CHUNK_BYTES * 2];
    while !region.is_empty() {
        let chunk_len = region.len().min(CHUNK_BYTES);
        let (chunk, rest) = region.split_at_mut(chunk_len);
        region = rest;
        rng.fill(&mut pool[..chunk_len * 2]);
        match file_type {
            FileType::Text => corrupt_text_chunk(chunk, threshold, &pool, rng),
            FileType::Image => corrupt_image_chunk(chunk, threshold, &pool),
            FileType::Audio => corrupt_audio_chunk(chunk, threshold, &pool),
        }
    }
}

/// Corrupts the R, G, and B channels of an RGBA payload chunk, each
/// independently, with probability threshold / 65536. Upholds the invariant that
/// the alpha channel is never touched: transparency is preserved so corruption
/// shows as color noise rather than transparency holes. The low byte of a fresh
/// u16 draw is the replacement, uniform over 0..=255.
///
/// Draws are consumed from `pool` strictly left to right, one per channel for
/// the decision and one more only when the channel is corrupted; leftover pool
/// entries are discarded, never reused.
fn corrupt_image_chunk(chunk: &mut [u8], threshold: u16, pool: &[u16]) {
    let mut draw = 0;
    for pixel in chunk.chunks_exact_mut(RGBA_BYTES_PER_PIXEL) {
        for channel in pixel.iter_mut().take(ALPHA_INDEX) {
            if pool[draw] < threshold {
                draw += 1;
                *channel = pool[draw] as u8;
            }
            draw += 1;
        }
    }
}

/// Corrupts a 16-bit audio payload chunk by displacing whole samples, each with
/// probability threshold / 65536, by a bounded random amount.
///
/// A sample is one value split across two bytes, not two independent bytes, so this
/// operates on the sample rather than on its bytes. Replacing the bytes outright would
/// throw the sample anywhere in the full range, and a single such sample is heard as a
/// full-scale click regardless of how gentle x is; replacing only the low byte caps the
/// total possible damage at about 0.8% of full scale, which is inaudible at any x. Both
/// make x mean something different for audio than it does for text and images.
///
/// Instead a selected sample is displaced by a random offset whose magnitude is bounded
/// by [`audio_noise_amplitude`], which scales with x. Low x is a light graininess, high
/// x swamps the signal, and the result saturates rather than wrapping, so decay never
/// flips a loud sample to the opposite extreme.
///
/// Substitution preserves length, so the clip keeps its duration, channel count, and
/// sample rate however far it decays.
fn corrupt_audio_chunk(chunk: &mut [u8], threshold: u16, pool: &[u16]) {
    let amplitude = audio_noise_amplitude(threshold);
    let mut draw = 0;
    for sample in chunk.chunks_exact_mut(AUDIO_BYTES_PER_SAMPLE) {
        if pool[draw] < threshold {
            draw += 1;
            // Map the draw onto a signed offset in [-amplitude, amplitude], then
            // saturate so a displaced sample clamps at the ends of the range instead
            // of wrapping around to the opposite sign.
            let span = amplitude.saturating_mul(2).saturating_add(1) as u32;
            let offset = (pool[draw] as u32 % span) as i32 - amplitude as i32;
            let old = i16::from_le_bytes([sample[0], sample[1]]) as i32;
            let new = (old + offset).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            sample.copy_from_slice(&new.to_le_bytes());
        }
        draw += 1;
    }
}

/// The maximum distance a corrupted audio sample may move from its original value.
///
/// Derived from the same threshold that sets how many samples are selected, so a single
/// x controls both how often decay lands and how hard it hits: at low x few samples move
/// and only slightly, at high x most samples move a long way. The two factors compound,
/// so the injected noise sits far below the payload at x = 1 and rises above it by
/// x = 10, which is the same span text and images cover.
fn audio_noise_amplitude(threshold: u16) -> u16 {
    let fraction = f64::from(threshold) / f64::from(u16::MAX);
    (fraction * f64::from(AUDIO_MAX_NOISE)) as u16
}

/// Corrupts a text payload chunk by replacing bytes, each independently with
/// probability threshold / 65536, with a uniformly random printable ASCII byte
/// (0x20 to 0x7E).
///
/// Operates on bytes, not Unicode codepoints, so at high x this can split or
/// break multi-byte UTF-8 sequences. The display layer substitutes the Unicode
/// replacement character for the resulting invalid sequences.
fn corrupt_text_chunk<R: RngCore>(chunk: &mut [u8], threshold: u16, pool: &[u16], rng: &mut R) {
    let mut draw = 0;
    for byte in chunk.iter_mut() {
        if pool[draw] < threshold {
            draw += 1;
            let r = pool[draw];
            // 689 full copies of 0..94 fit in [0, 65455), so this maps a draw
            // to an exactly uniform replacement without rejection. The rare
            // high draw falls back to a direct uniform draw from the stream.
            *byte = if r < TEXT_REPLACEMENT_ACCEPT_MAX {
                PRINTABLE_ASCII_LOW + (r % PRINTABLE_ASCII_COUNT) as u8
            } else {
                rng.gen_range(PRINTABLE_ASCII_LOW..=PRINTABLE_ASCII_HIGH)
            };
        }
        draw += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Tolerance for comparing an observed corruption fraction against its expected
    /// probability, as specified by the milestone.
    const FRACTION_TOLERANCE: f64 = 0.01;

    /// Counts how many bytes differ between two equally sized slices.
    fn changed_count(before: &[u8], after: &[u8]) -> usize {
        before
            .iter()
            .zip(after.iter())
            .filter(|(a, b)| a != b)
            .count()
    }

    #[test]
    fn probability_matches_known_values() {
        // x = 1 gives roughly 0.095; x = 10 gives roughly 0.632.
        assert!((corruption_probability(1.0) - 0.095).abs() < 0.001);
        assert!((corruption_probability(10.0) - 0.632).abs() < 0.001);
    }

    #[test]
    fn threshold_quantization_stays_within_one_65536th() {
        // The integer threshold deviates from the continuous probability by at
        // most 1 / 65536 for every x the format can express.
        for x in [0.5, 1.0, 2.0, 5.0, 10.0, 25.0] {
            let p = corruption_probability(x);
            let t = probability_threshold(x);
            assert!((t as f64 / 65536.0 - p).abs() <= 1.0 / 65536.0 + 1e-12);
        }
    }

    #[test]
    fn text_corruption_fraction_matches_probability() {
        // An all-zero payload makes measurement exact: a corruption replacement is
        // always printable ASCII (never zero), so every selected byte visibly changes
        // and the changed fraction equals the selection probability.
        for (x, expected) in [(1.0, 0.095), (10.0, 0.632)] {
            let original = vec![0u8; 100_000];
            let mut payload = original.clone();
            corrupt(&mut payload, FileType::Text, x);
            let fraction = changed_count(&original, &payload) as f64 / original.len() as f64;
            assert!(
                (fraction - expected).abs() < FRACTION_TOLERANCE,
                "x={x} text fraction {fraction} not within {FRACTION_TOLERANCE} of {expected}",
            );
        }
    }

    #[test]
    fn audio_displaces_about_the_expected_share_of_samples() {
        // Audio displaces whole samples rather than replacing bytes, so the measurement
        // is over samples. A displaced sample can land back on its original value, which
        // is rare enough at this amplitude to sit inside the tolerance.
        let original = vec![0u8; 100_000];
        let mut payload = original.clone();
        corrupt(&mut payload, FileType::Audio, 10.0);

        let changed = original
            .chunks_exact(AUDIO_BYTES_PER_SAMPLE)
            .zip(payload.chunks_exact(AUDIO_BYTES_PER_SAMPLE))
            .filter(|(before, after)| before != after)
            .count();
        let total = original.len() / AUDIO_BYTES_PER_SAMPLE;
        let fraction = changed as f64 / total as f64;
        assert!(
            (fraction - 0.632).abs() < FRACTION_TOLERANCE,
            "x=10 displaced {fraction} of samples, expected near 0.632",
        );
    }

    #[test]
    fn audio_displacement_is_bounded_and_scales_with_x() {
        // No sample may move further than the amplitude x allows, and a higher x must
        // move samples further. This is what keeps a single open from turning a quiet
        // sample into a full-scale click, which is how x stays comparable to the other
        // payload types.
        fn mean_shift(x: f64) -> f64 {
            // A mid-scale sample everywhere, so displacement in either direction is
            // measurable without saturating at the ends of the range.
            let original: Vec<u8> = (0..50_000).flat_map(|_| 8_000i16.to_le_bytes()).collect();
            let mut payload = original.clone();
            corrupt(&mut payload, FileType::Audio, x);

            let shifts: Vec<i32> = original
                .chunks_exact(AUDIO_BYTES_PER_SAMPLE)
                .zip(payload.chunks_exact(AUDIO_BYTES_PER_SAMPLE))
                .map(|(before, after)| {
                    let before = i16::from_le_bytes([before[0], before[1]]) as i32;
                    let after = i16::from_le_bytes([after[0], after[1]]) as i32;
                    (after - before).abs()
                })
                .collect();

            let bound = i32::from(audio_noise_amplitude(probability_threshold(x)));
            assert!(
                shifts.iter().all(|shift| *shift <= bound),
                "a sample moved further than the amplitude x allows"
            );
            shifts.iter().sum::<i32>() as f64 / shifts.len() as f64
        }

        let gentle = mean_shift(1.0);
        let severe = mean_shift(10.0);
        assert!(
            severe > gentle * 4.0,
            "x=10 mean shift {severe} was not well above x=1 mean shift {gentle}"
        );
    }

    #[test]
    fn audio_corruption_preserves_length() {
        // Length preservation is what keeps a decayed clip at its original duration,
        // channel count, and sample rate however far it rots.
        let original = vec![7u8; 4096];
        let mut payload = original.clone();
        corrupt(&mut payload, FileType::Audio, 10.0);
        assert_eq!(
            payload.len(),
            original.len(),
            "audio corruption must never change the payload length"
        );
    }

    #[test]
    fn audio_trailing_partial_sample_is_untouched() {
        // An odd-length payload cannot end on a 16-bit sample boundary. The trailing
        // byte is left alone so the payload always ends on a whole sample.
        let mut payload = vec![0u8; 8193];
        corrupt(&mut payload, FileType::Audio, 10.0);
        assert_eq!(
            payload[8192], 0,
            "the trailing partial sample must not be corrupted"
        );
    }

    #[test]
    fn higher_x_corrupts_at_least_as_much_as_lower_x_on_average() {
        // Across 50 trials, the mean corruption at a higher x must be greater than
        // at a lower x on equivalent payloads. Randomness is unseeded, so this is a
        // statistical property over many trials, not a per-trial guarantee.
        const TRIALS: usize = 50;
        const LEN: usize = 10_000;
        let low_x = 2.0;
        let high_x = 8.0;

        let mut low_total = 0usize;
        let mut high_total = 0usize;
        for _ in 0..TRIALS {
            let original = vec![0u8; LEN];

            let mut low_payload = original.clone();
            corrupt(&mut low_payload, FileType::Text, low_x);
            low_total += changed_count(&original, &low_payload);

            let mut high_payload = original.clone();
            corrupt(&mut high_payload, FileType::Text, high_x);
            high_total += changed_count(&original, &high_payload);
        }

        assert!(
            high_total > low_total,
            "higher x mean corruption ({}) was not greater than lower x ({})",
            high_total,
            low_total
        );
    }

    #[test]
    fn image_alpha_channel_is_never_modified() {
        // Build an RGBA payload with a recognizable alpha sentinel, corrupt it at a
        // high x many times, and confirm every alpha byte survives untouched.
        const PIXELS: usize = 2_000;
        const ALPHA_SENTINEL: u8 = 0xAB;
        const RUNS: usize = 20;

        for _ in 0..RUNS {
            let mut payload = Vec::with_capacity(PIXELS * RGBA_BYTES_PER_PIXEL);
            for _ in 0..PIXELS {
                payload.extend_from_slice(&[0x00, 0x00, 0x00, ALPHA_SENTINEL]);
            }

            corrupt(&mut payload, FileType::Image, 10.0);

            for pixel in payload.chunks_exact(RGBA_BYTES_PER_PIXEL) {
                assert_eq!(
                    pixel[ALPHA_INDEX], ALPHA_SENTINEL,
                    "alpha channel was modified by corruption"
                );
            }
        }
    }

    #[test]
    fn image_rgb_corruption_fraction_is_near_expected() {
        // Measure the corruption fraction over R, G, B channels only (alpha is
        // excluded by the algorithm). All channels start at zero so a replacement
        // is detectable except for the 1-in-256 case where a random byte lands on
        // zero again, which keeps the observed fraction within tolerance.
        const PIXELS: usize = 50_000;
        let mut payload = vec![0u8; PIXELS * RGBA_BYTES_PER_PIXEL];
        corrupt(&mut payload, FileType::Image, 10.0);

        let mut changed = 0usize;
        let rgb_channels = PIXELS * 3;
        for pixel in payload.chunks_exact(RGBA_BYTES_PER_PIXEL) {
            for channel in pixel.iter().take(ALPHA_INDEX) {
                if *channel != 0 {
                    changed += 1;
                }
            }
        }

        let fraction = changed as f64 / rgb_channels as f64;
        assert!(
            (fraction - 0.632).abs() < FRACTION_TOLERANCE,
            "x=10 image RGB fraction {} not within {} of 0.632",
            fraction,
            FRACTION_TOLERANCE
        );
    }

    /// All payloads below the parallel threshold exercise the serial path; the
    /// following large-payload tests push corruption onto the rayon path and
    /// across region boundaries.

    #[test]
    fn image_alpha_never_modified_large_parallel() {
        // An 8 MiB RGBA payload with an alpha sentinel forces the parallel path
        // (>= PAR_MIN_BYTES) and spans multiple 4 MiB regions, so alpha survival
        // is checked across region boundaries.
        const PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
        const ALPHA_SENTINEL: u8 = 0xCD;
        let mut payload = Vec::with_capacity(PAYLOAD_BYTES);
        while payload.len() < PAYLOAD_BYTES {
            payload.extend_from_slice(&[0x00, 0x00, 0x00, ALPHA_SENTINEL]);
        }

        corrupt(&mut payload, FileType::Image, 10.0);

        assert_eq!(
            payload.len(),
            PAYLOAD_BYTES,
            "corruption changed the length"
        );
        for pixel in payload.chunks_exact(RGBA_BYTES_PER_PIXEL) {
            assert_eq!(
                pixel[ALPHA_INDEX], ALPHA_SENTINEL,
                "alpha channel was modified by parallel corruption"
            );
        }
    }

    #[test]
    fn large_image_rgb_fraction_near_expected() {
        // 8 MiB RGBA payload forces the parallel path; only R, G, B channels
        // count, and the 1-in-256 chance a replacement lands on zero keeps the
        // observed fraction within tolerance.
        let payload = vec![0u8; 8 * 1024 * 1024];
        for (x, expected) in [(1.0, 0.095), (10.0, 0.632)] {
            let mut corrupted = payload.clone();
            corrupt(&mut corrupted, FileType::Image, x);

            let mut changed = 0usize;
            for pixel in corrupted.chunks_exact(RGBA_BYTES_PER_PIXEL) {
                for channel in pixel.iter().take(ALPHA_INDEX) {
                    if *channel != 0 {
                        changed += 1;
                    }
                }
            }
            let rgb_channels = corrupted.len() / RGBA_BYTES_PER_PIXEL * 3;
            let fraction = changed as f64 / rgb_channels as f64;
            assert!(
                (fraction - expected).abs() < FRACTION_TOLERANCE,
                "x={} image RGB fraction {} not within {} of {}",
                x,
                fraction,
                FRACTION_TOLERANCE,
                expected
            );
        }
    }

    #[test]
    fn image_trailing_bytes_untouched() {
        // A payload that is not a whole number of pixels leaves its trailing
        // bytes alone, exactly as a well-formed RGBA payload's remainder should.
        const PIXELS: usize = 1_000;
        const TRAILING: [u8; 2] = [0xDE, 0xAD];
        let mut payload = vec![0u8; PIXELS * RGBA_BYTES_PER_PIXEL];
        payload.extend_from_slice(&TRAILING);

        corrupt(&mut payload, FileType::Image, 10.0);

        assert_eq!(
            &payload[payload.len() - TRAILING.len()..],
            &TRAILING,
            "trailing bytes were modified by image corruption"
        );
    }

    #[test]
    fn region_worker_reproduces_with_seeded_rng() {
        // The pool-indexing logic is deterministic for a fixed stream: the same
        // seed through the region worker must reproduce byte-identical output.
        // This guards the draw accounting; the statistical tests guard the
        // distribution.
        let threshold = probability_threshold(10.0);
        let original: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();

        let mut a = original.clone();
        region_work(
            &mut a,
            FileType::Text,
            threshold,
            &mut StdRng::seed_from_u64(27325),
        );
        let mut b = original.clone();
        region_work(
            &mut b,
            FileType::Text,
            threshold,
            &mut StdRng::seed_from_u64(27325),
        );
        assert_eq!(a, b, "same seed must reproduce identical corruption");

        let image_payload = vec![0u8; 4_000 * RGBA_BYTES_PER_PIXEL];
        let mut image_a = image_payload.clone();
        region_work(
            &mut image_a,
            FileType::Image,
            threshold,
            &mut StdRng::seed_from_u64(27325),
        );
        let mut image_b = image_payload.clone();
        region_work(
            &mut image_b,
            FileType::Image,
            threshold,
            &mut StdRng::seed_from_u64(27325),
        );
        assert_eq!(
            image_a, image_b,
            "same seed must reproduce identical corruption"
        );
    }
}
