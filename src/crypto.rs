//! v2 cryptographic primitives.
//!
//! These are the raw building blocks for the v2 encrypted, TPM-hardware-bound format. A
//! v2 file is always bound to a TPM at encode time (no passphrase, no portable key). The
//! random 256-bit content key `K` encrypts the canonical payload and is sealed to the
//! TPM (sealing is not implemented here). This module only performs the payload
//! AES-256-GCM encryption/decryption and key/nonce generation.
//!
//! `ContentKey` and `PayloadNonce` are separate, dedicated types so the payload key and
//! nonce cannot be swapped with anything else. The canonical ciphertext is created once
//! and is never re-encrypted, so the payload nonce is generated once and stored in the
//! header. Sensitive key material is zeroized on drop.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::DecayError;

/// The random 256-bit content key `K`, used to encrypt the canonical payload.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ContentKey([u8; 32]);

/// A 96-bit nonce used to encrypt the canonical payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadNonce([u8; 12]);

impl ContentKey {
    /// Borrows the key bytes as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Wraps 32 raw bytes (for example recovered from a TPM unseal) into a content key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ContentKey(bytes)
    }
}

impl PayloadNonce {
    /// Borrows the nonce bytes as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Wraps 12 raw bytes (for example read from a v2 header) into a payload nonce.
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        PayloadNonce(bytes)
    }
}

/// Draws `N` bytes from the operating system's cryptographically secure generator.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

/// Generates a fresh random 256-bit content key `K`.
pub fn generate_content_key() -> ContentKey {
    ContentKey(random_bytes::<32>())
}

/// Generates a fresh random nonce for encrypting the canonical payload.
pub fn generate_payload_nonce() -> PayloadNonce {
    PayloadNonce(random_bytes::<12>())
}

/// Encrypts the canonical plaintext under `content_key` with AES-256-GCM using
/// `payload_nonce`, authenticating `aad`. The caller must supply a `payload_nonce` used
/// at most once per `content_key`.
pub fn encrypt_payload(
    content_key: &ContentKey,
    plaintext: &[u8],
    payload_nonce: &PayloadNonce,
    aad: &[u8],
) -> Result<Vec<u8>, DecayError> {
    let cipher =
        Aes256Gcm::new_from_slice(content_key.as_bytes()).map_err(|_| DecayError::Crypto {
            context: "invalid payload key length".to_string(),
        })?;
    let nonce = Nonce::from_slice(payload_nonce.as_bytes());
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| DecayError::Crypto {
            context: "failed to encrypt payload".to_string(),
        })
}

/// Decrypts the canonical ciphertext under `content_key` with AES-256-GCM using
/// `payload_nonce` and the same `aad`. A wrong key, tampered ciphertext, or mismatched
/// `aad` yields [`DecayError::Crypto`], never a panic.
pub fn decrypt_payload(
    content_key: &ContentKey,
    ciphertext: &[u8],
    payload_nonce: &PayloadNonce,
    aad: &[u8],
) -> Result<Vec<u8>, DecayError> {
    let cipher =
        Aes256Gcm::new_from_slice(content_key.as_bytes()).map_err(|_| DecayError::Crypto {
            context: "invalid payload key length".to_string(),
        })?;
    let nonce = Nonce::from_slice(payload_nonce.as_bytes());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| DecayError::Crypto {
            context: "failed to decrypt payload: authentication failed".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_encrypt_decrypt_returns_same_plaintext() {
        let key = generate_content_key();
        let nonce = generate_payload_nonce();
        let plaintext: &[u8] = b"the quick brown fox";
        let ct = encrypt_payload(&key, plaintext, &nonce, b"").expect("encrypt");
        let pt = decrypt_payload(&key, &ct, &nonce, b"").expect("decrypt");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails_payload() {
        let key_ok = generate_content_key();
        let key_bad = generate_content_key();
        let nonce = generate_payload_nonce();
        let ct = encrypt_payload(&key_ok, b"data", &nonce, b"").expect("encrypt");
        assert!(matches!(
            decrypt_payload(&key_bad, &ct, &nonce, b""),
            Err(DecayError::Crypto { .. })
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = generate_content_key();
        let nonce = generate_payload_nonce();
        let mut ct = encrypt_payload(&key, b"data", &nonce, b"").expect("encrypt");
        ct[0] ^= 0xFF;
        assert!(matches!(
            decrypt_payload(&key, &ct, &nonce, b""),
            Err(DecayError::Crypto { .. })
        ));
    }

    #[test]
    fn tampered_aad_fails() {
        let key = generate_content_key();
        let nonce = generate_payload_nonce();
        let ct = encrypt_payload(&key, b"data", &nonce, b"aad").expect("encrypt");
        assert!(matches!(
            decrypt_payload(&key, &ct, &nonce, b"other"),
            Err(DecayError::Crypto { .. })
        ));
    }

    #[test]
    fn empty_plaintext_works() {
        let key = generate_content_key();
        let nonce = generate_payload_nonce();
        let ct = encrypt_payload(&key, b"", &nonce, b"").expect("encrypt");
        let pt = decrypt_payload(&key, &ct, &nonce, b"").expect("decrypt");
        assert!(pt.is_empty(), "decrypted empty plaintext must be empty");
    }
}
