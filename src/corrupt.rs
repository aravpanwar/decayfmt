//! Corruption algorithms for image and text payloads.
//!
//! These are pure functions over byte slices. There is no file I/O and no CLI
//! logic here; the caller is responsible for reading the payload, calling into
//! this module, and writing the result back. The invariant this module upholds is
//! that corruption is always stochastic and always sourced from the operating
//! system CSPRNG. It is never seeded and never deterministic, because deterministic
//! corruption would let someone reconstruct the corruption sequence and undo it.

use crate::format::FileType;
use rand::Rng;

/// The divisor in the corruption probability curve p = 1 - exp(-x / DECAY_SCALE).
///
/// It is the tuning constant that sets how a given x feels. Lowering it makes
/// every x more destructive (the curve rises toward p = 1 faster); raising it
/// makes every x gentler (more opens are needed to reach the same damage). At the
/// current value of 10, x = 1 corrupts roughly 9.5% of eligible bytes per open and
/// x = 10 corrupts roughly 63%. Changing this number changes the meaning of every
/// existing filename's x, so it is treated as part of the format's feel, not a
/// free parameter.
const DECAY_SCALE: f64 = 10.0;

/// Number of bytes per pixel in an RGBA image payload.
const RGBA_BYTES_PER_PIXEL: usize = 4;

/// Index of the alpha channel within an RGBA pixel. This byte is never corrupted.
const ALPHA_INDEX: usize = 3;

/// Lowest printable ASCII byte used as a text corruption replacement (space).
const PRINTABLE_ASCII_LOW: u8 = 0x20;

/// Highest printable ASCII byte used as a text corruption replacement (tilde).
const PRINTABLE_ASCII_HIGH: u8 = 0x7E;

/// Derives the per-byte corruption probability from the instability value x.
///
/// p = 1 - exp(-x / DECAY_SCALE). The exponential form makes p climb smoothly from
/// 0 toward 1 as x grows, without ever needing to clamp. x must be positive; the
/// caller is responsible for having validated that before reaching this module.
fn corruption_probability(x: f64) -> f64 {
    1.0 - (-x / DECAY_SCALE).exp()
}

/// Corrupts a payload in place according to its file type and instability value x.
///
/// Mutates the slice directly. Randomness comes from the OS CSPRNG via
/// `rand::thread_rng`, freshly per call, so two opens of the same bytes produce
/// different results. Upholds the invariant that the corruption is never seeded.
pub fn corrupt(payload: &mut [u8], file_type: FileType, x: f64) {
    let probability = corruption_probability(x);
    let mut rng = rand::thread_rng();
    match file_type {
        FileType::Image => corrupt_image(payload, probability, &mut rng),
        FileType::Text => corrupt_text(payload, probability, &mut rng),
    }
}

/// Corrupts the R, G, and B channels of an RGBA payload, each independently, with
/// the given probability. Upholds the invariant that the alpha channel is never
/// touched: transparency is preserved so corruption shows as color noise rather
/// than transparency holes. Any trailing bytes that do not form a whole pixel are
/// left untouched, since a well-formed RGBA payload is a whole number of pixels.
fn corrupt_image<R: Rng>(payload: &mut [u8], probability: f64, rng: &mut R) {
    for pixel in payload.chunks_exact_mut(RGBA_BYTES_PER_PIXEL) {
        for (index, channel) in pixel.iter_mut().enumerate() {
            if index == ALPHA_INDEX {
                continue;
            }
            if rng.gen::<f64>() < probability {
                *channel = rng.gen::<u8>();
            }
        }
    }
}

/// Corrupts a text payload by replacing bytes, each independently with the given
/// probability, with a uniformly random printable ASCII byte (0x20 to 0x7E).
///
/// Operates on bytes, not Unicode codepoints, so at high x this can split or break
/// multi-byte UTF-8 sequences. That is intended: the display layer is responsible
/// for substituting the Unicode replacement character for whatever is no longer
/// valid. This module only damages bytes.
fn corrupt_text<R: Rng>(payload: &mut [u8], probability: f64, rng: &mut R) {
    for byte in payload.iter_mut() {
        if rng.gen::<f64>() < probability {
            *byte = rng.gen_range(PRINTABLE_ASCII_LOW..=PRINTABLE_ASCII_HIGH);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn text_corruption_fraction_at_x1_is_near_expected() {
        // An all-zero payload makes measurement exact: a corruption replacement is
        // always printable ASCII (never zero), so every selected byte visibly
        // changes and the changed fraction equals the selection probability.
        let original = vec![0u8; 100_000];
        let mut payload = original.clone();
        corrupt(&mut payload, FileType::Text, 1.0);
        let fraction = changed_count(&original, &payload) as f64 / original.len() as f64;
        assert!(
            (fraction - 0.095).abs() < FRACTION_TOLERANCE,
            "x=1 text fraction {} not within {} of 0.095",
            fraction,
            FRACTION_TOLERANCE
        );
    }

    #[test]
    fn text_corruption_fraction_at_x10_is_near_expected() {
        let original = vec![0u8; 100_000];
        let mut payload = original.clone();
        corrupt(&mut payload, FileType::Text, 10.0);
        let fraction = changed_count(&original, &payload) as f64 / original.len() as f64;
        assert!(
            (fraction - 0.632).abs() < FRACTION_TOLERANCE,
            "x=10 text fraction {} not within {} of 0.632",
            fraction,
            FRACTION_TOLERANCE
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
        const RUNS: usize = 1_000;

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
}
