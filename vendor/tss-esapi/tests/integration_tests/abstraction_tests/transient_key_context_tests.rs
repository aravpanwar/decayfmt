// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    abstraction::{
        ek,
        transient::{KeyParams, ObjectWrapper, TransientKeyContextBuilder},
        AsymmetricAlgorithmSelection,
    },
    constants::response_code::Tss2ResponseCodeKind,
    interface_types::{
        algorithm::{
            AsymmetricAlgorithm, EccSchemeAlgorithm, HashingAlgorithm, RsaSchemeAlgorithm,
        },
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        Auth, CreateKeyResult, Digest, EccScheme, Public, PublicKeyRsa, RsaExponent, RsaScheme,
        RsaSignature, Signature, SymmetricDefinitionObject,
    },
    utils::{create_restricted_decryption_rsa_public, PublicKey},
    Error, TransientKeyContext, WrapperErrorKind as ErrorKind,
};

use crate::common::create_tcti;

const HASH: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

fn create_ctx() -> TransientKeyContext {
    TransientKeyContextBuilder::new()
        .with_tcti(create_tcti())
        .build()
        .unwrap()
}

#[test]
fn wrong_key_sizes() {
    assert_eq!(
        TransientKeyContextBuilder::new()
            .with_tcti(create_tcti())
            .with_root_key_size(1023)
            .build()
            .unwrap_err(),
        Error::WrapperError(ErrorKind::InvalidParam)
    );
    assert_eq!(
        TransientKeyContextBuilder::new()
            .with_tcti(create_tcti())
            .with_root_key_size(1025)
            .build()
            .unwrap_err(),
        Error::WrapperError(ErrorKind::InvalidParam)
    );
    assert_eq!(
        TransientKeyContextBuilder::new()
            .with_tcti(create_tcti())
            .with_root_key_size(2047)
            .build()
            .unwrap_err(),
        Error::WrapperError(ErrorKind::InvalidParam)
    );
    assert_eq!(
        TransientKeyContextBuilder::new()
            .with_tcti(create_tcti())
            .with_root_key_size(2049)
            .build()
            .unwrap_err(),
        Error::WrapperError(ErrorKind::InvalidParam)
    );
}

#[test]
fn wrong_auth_size() {
    assert_eq!(
        TransientKeyContextBuilder::new()
            .with_tcti(create_tcti())
            .with_root_key_auth_size(33)
            .build()
            .unwrap_err(),
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
}

#[test]
fn load_bad_sized_key() {
    let mut ctx = create_ctx();
    let key_params = KeyParams::Rsa {
        size: RsaKeyBits::Rsa1024,
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        pub_exponent: RsaExponent::default(),
    };
    let _ = ctx
        .load_external_public_key(PublicKey::Rsa(vec![0xDE, 0xAD, 0xBE, 0xEF]), key_params)
        .unwrap_err();
}

#[test]
fn load_with_invalid_params() {
    let pub_key = vec![
        0x96, 0xDC, 0x72, 0x77, 0x49, 0x82, 0xFD, 0x2D, 0x06, 0x65, 0x8C, 0xE5, 0x3A, 0xCD, 0xED,
        0xBD, 0x50, 0xD7, 0x6F, 0x3B, 0xE5, 0x6A, 0x76, 0xED, 0x3E, 0xD8, 0xF9, 0x93, 0x40, 0x55,
        0x86, 0x6F, 0xBE, 0x76, 0x60, 0xD2, 0x03, 0x23, 0x59, 0x19, 0x8D, 0xFC, 0x51, 0x6A, 0x95,
        0xC8, 0x5D, 0x5A, 0x89, 0x4D, 0xE5, 0xEA, 0x44, 0x78, 0x29, 0x62, 0xDB, 0x3F, 0xF0, 0xF7,
        0x49, 0x15, 0xA5, 0xAE, 0x6D, 0x81, 0x8F, 0x06, 0x7B, 0x0B, 0x50, 0x7A, 0x2F, 0xEB, 0x00,
        0xB6, 0x12, 0xF3, 0x10, 0xAF, 0x4D, 0x4A, 0xA9, 0xD9, 0x81, 0xBB, 0x1E, 0x2B, 0xDF, 0xB9,
        0x33, 0x3D, 0xD6, 0xB7, 0x8D, 0x23, 0x7C, 0x7F, 0xE7, 0x12, 0x48, 0x4F, 0x26, 0x73, 0xAF,
        0x63, 0x51, 0xA9, 0xDB, 0xA4, 0xAB, 0xB7, 0x27, 0x00, 0xD7, 0x1C, 0xFC, 0x2F, 0x61, 0x2A,
        0xB9, 0x5B, 0x66, 0xA0, 0xE0, 0xD8, 0xF3, 0xD9,
    ];

    let key_params = KeyParams::Ecc {
        curve: EccCurve::NistP256,
        scheme: EccScheme::create(
            EccSchemeAlgorithm::EcDsa,
            Some(HashingAlgorithm::Sha256),
            None,
        )
        .expect("Failed to create ecc scheme"),
    };
    let mut ctx = create_ctx();
    let _ = ctx
        .load_external_public_key(PublicKey::Rsa(pub_key), key_params)
        .unwrap_err();
}

#[test]
fn verify() {
    let pub_key = vec![
        0x96, 0xDC, 0x72, 0x77, 0x49, 0x82, 0xFD, 0x2D, 0x06, 0x65, 0x8C, 0xE5, 0x3A, 0xCD, 0xED,
        0xBD, 0x50, 0xD7, 0x6F, 0x3B, 0xE5, 0x6A, 0x76, 0xED, 0x3E, 0xD8, 0xF9, 0x93, 0x40, 0x55,
        0x86, 0x6F, 0xBE, 0x76, 0x60, 0xD2, 0x03, 0x23, 0x59, 0x19, 0x8D, 0xFC, 0x51, 0x6A, 0x95,
        0xC8, 0x5D, 0x5A, 0x89, 0x4D, 0xE5, 0xEA, 0x44, 0x78, 0x29, 0x62, 0xDB, 0x3F, 0xF0, 0xF7,
        0x49, 0x15, 0xA5, 0xAE, 0x6D, 0x81, 0x8F, 0x06, 0x7B, 0x0B, 0x50, 0x7A, 0x2F, 0xEB, 0x00,
        0xB6, 0x12, 0xF3, 0x10, 0xAF, 0x4D, 0x4A, 0xA9, 0xD9, 0x81, 0xBB, 0x1E, 0x2B, 0xDF, 0xB9,
        0x33, 0x3D, 0xD6, 0xB7, 0x8D, 0x23, 0x7C, 0x7F, 0xE7, 0x12, 0x48, 0x4F, 0x26, 0x73, 0xAF,
        0x63, 0x51, 0xA9, 0xDB, 0xA4, 0xAB, 0xB7, 0x27, 0x00, 0xD7, 0x1C, 0xFC, 0x2F, 0x61, 0x2A,
        0xB9, 0x5B, 0x66, 0xA0, 0xE0, 0xD8, 0xF3, 0xD9,
    ];

    // "Les carottes sont cuites." hashed with SHA256
    let digest = Digest::try_from(vec![
        0x02, 0x2b, 0x26, 0xb1, 0xc3, 0x18, 0xdb, 0x73, 0x36, 0xef, 0x6f, 0x50, 0x9c, 0x35, 0xdd,
        0xaa, 0xe1, 0x3d, 0x21, 0xdf, 0x83, 0x68, 0x0f, 0x48, 0xae, 0x5d, 0x8a, 0x5d, 0x37, 0x3c,
        0xc1, 0x05,
    ])
    .unwrap();

    let signature = Signature::RsaSsa(
        RsaSignature::create(
            HashingAlgorithm::Sha256,
            PublicKeyRsa::try_from(vec![
                0x8c, 0xf8, 0x87, 0x3a, 0xb2, 0x9a, 0x18, 0xf9, 0xe0, 0x2e, 0xb9, 0x2d, 0xe7, 0xc8,
                0x32, 0x12, 0xd6, 0xd9, 0x2d, 0x98, 0xec, 0x9e, 0x47, 0xb7, 0x5b, 0x26, 0x86, 0x9d,
                0xf5, 0xa2, 0x6b, 0x8b, 0x6f, 0x00, 0xd3, 0xbb, 0x68, 0x88, 0xe1, 0xad, 0xcf, 0x1c,
                0x09, 0x81, 0x91, 0xbf, 0xee, 0xce, 0x4f, 0xb5, 0x83, 0x3c, 0xf5, 0xb0, 0xfa, 0x68,
                0x69, 0xde, 0x7b, 0xe8, 0x49, 0x69, 0x40, 0xad, 0x90, 0xf1, 0x7f, 0x31, 0xf2, 0x75,
                0x4e, 0x1c, 0x52, 0x92, 0x72, 0x2e, 0x0b, 0x06, 0xe7, 0x32, 0xb4, 0x5e, 0x82, 0x8b,
                0x39, 0x72, 0x24, 0x5f, 0xee, 0x17, 0xae, 0x2d, 0x77, 0x53, 0xff, 0x1a, 0xad, 0x12,
                0x83, 0x4f, 0xb5, 0x52, 0x92, 0x6e, 0xda, 0xb2, 0x55, 0x77, 0xa7, 0x58, 0xcc, 0x10,
                0xa6, 0x7f, 0xc5, 0x26, 0x4e, 0x5b, 0x75, 0x9d, 0x83, 0x05, 0x9f, 0x99, 0xde, 0xc6,
                0xf5, 0x12,
            ])
            .expect("Failed to create Public RSA key structure for RSA signature"),
        )
        .expect("Failed to create RSA signature"),
    );

    let mut ctx = create_ctx();
    let key_params = KeyParams::Rsa {
        size: RsaKeyBits::Rsa1024,
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        pub_exponent: RsaExponent::default(),
    };
    let pub_key = ctx
        .load_external_public_key(PublicKey::Rsa(pub_key), key_params)
        .unwrap();
    let _ = ctx
        .verify_signature(pub_key, key_params, digest, signature)
        .expect("the signature should be valid");
}

#[test]
fn sign_with_bad_auth() {
    let mut ctx = create_ctx();
    let key_params = KeyParams::Rsa {
        size: RsaKeyBits::Rsa2048,
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        pub_exponent: RsaExponent::default(),
    };
    let (key, key_auth) = ctx.create_key(key_params, 16).unwrap();
    let auth_value = key_auth.unwrap();
    let mut bad_auth_values = auth_value.value().to_vec();
    bad_auth_values[6..10].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    ctx.sign(
        key,
        key_params,
        Some(Auth::try_from(bad_auth_values).unwrap()),
        Digest::try_from(HASH.to_vec()).unwrap(),
    )
    .unwrap_err();
}

#[test]
fn sign_with_no_auth() {
    let mut ctx = create_ctx();
    let key_params = KeyParams::Rsa {
        size: RsaKeyBits::Rsa2048,
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        pub_exponent: RsaExponent::default(),
    };
    let (key, _) = ctx.create_key(key_params, 16).unwrap();
    ctx.sign(
        key,
        key_params,
        None,
        Digest::try_from(HASH.to_vec()).unwrap(),
    )
    .unwrap_err();
}

#[test]
fn encrypt_decrypt() {
    let mut ctx = create_ctx();
    let key_params = KeyParams::Rsa {
        size: RsaKeyBits::Rsa2048,
        scheme: RsaScheme::create(RsaSchemeAlgorithm::Oaep, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        pub_exponent: RsaExponent::default(),
    };
    let (dec_key, auth) = ctx.create_key(key_params, 16).unwrap();
    let enc_key = ctx
        .load_external_public_key(dec_key.public().clone(), key_params)
        .unwrap();
    let message = vec![0x1, 0x2, 0x3];

    let ciphertext = ctx
        .rsa_encrypt(
            enc_key,
            key_params,
            None,
            PublicKeyRsa::try_from(message.clone()).unwrap(),
            None,
        )
        .unwrap();
    assert_ne!(message, ciphertext.value());

    let plaintext = ctx
        .rsa_decrypt(dec_key, key_params, auth, ciphertext, None)
        .unwrap();
    assert_eq!(message, plaintext.value());
}

#[test]
fn two_signatures_different_digest() {
    let mut ctx = create_ctx();
    let key_params1 = KeyParams::Rsa {
        size: RsaKeyBits::Rsa2048,
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        pub_exponent: RsaExponent::default(),
    };
    let (key1, auth1) = ctx.create_key(key_params1, 16).unwrap();
    let key_params2 = KeyParams::Rsa {
        size: RsaKeyBits::Rsa2048,
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        pub_exponent: RsaExponent::default(),
    };
    let (key2, auth2) = ctx.create_key(key_params2, 16).unwrap();
    let signature1 = ctx
        .sign(
            key1,
            key_params1,
            auth1,
            Digest::try_from(HASH.to_vec()).unwrap(),
        )
        .unwrap();
    let signature2 = ctx
        .sign(
            key2,
            key_params2,
            auth2,
            Digest::try_from(HASH.to_vec()).unwrap(),
        )
        .unwrap();

    if let Signature::RsaSsa(rsa_signature_1) = signature1 {
        if let Signature::RsaSsa(rsa_signature_2) = signature2 {
            assert!(
                rsa_signature_1.signature().value().to_vec()
                    != rsa_signature_2.signature().value().to_vec()
            );
        } else {
            panic!("Unexpected signature for signature 2");
        }
    } else {
        panic!("Unexpected singature for signature 1");
    }
}

#[test]
fn verify_wrong_key() {
    let mut ctx = create_ctx();
    let key_params1 = KeyParams::Rsa {
        size: RsaKeyBits::Rsa2048,
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        pub_exponent: RsaExponent::default(),
    };
    let (key1, auth1) = ctx.create_key(key_params1, 16).unwrap();

    let key_params2 = KeyParams::Rsa {
        size: RsaKeyBits::Rsa2048,
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        pub_exponent: RsaExponent::default(),
    };
    let (key2, _) = ctx.create_key(key_params2, 16).unwrap();

    // Sign with the first key
    let signature = ctx
        .sign(
            key1,
            key_params1,
            auth1,
            Digest::try_from(HASH.to_vec()).unwrap(),
        )
        .unwrap();

    // Import and verify with the second key
    let pub_key = ctx
        .load_external_public_key(key2.public().clone(), key_params2)
        .unwrap();
    if let Error::Tss2Error(error) = ctx
        .verify_signature(
            pub_key,
            key_params2,
            Digest::try_from(HASH.to_vec()).unwrap(),
            signature,
        )
        .unwrap_err()
    {
        assert_eq!(error.kind(), Some(Tss2ResponseCodeKind::Signature));
    } else {
        panic!("The signature verification should have failed with an invalid signature error.");
    }
}
#[test]
fn verify_wrong_digest() {
    let mut ctx = create_ctx();
    let key_params = KeyParams::Rsa {
        size: RsaKeyBits::Rsa2048,
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        pub_exponent: RsaExponent::default(),
    };
    let (key, auth) = ctx.create_key(key_params, 16).unwrap();

    let signature = ctx
        .sign(
            key.clone(),
            key_params,
            auth,
            Digest::try_from(HASH.to_vec()).unwrap(),
        )
        .unwrap();
    let pub_key = ctx
        .load_external_public_key(key.public().clone(), key_params)
        .unwrap();

    let mut digest_values = HASH.to_vec();
    digest_values[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    if let Error::Tss2Error(error) = ctx
        .verify_signature(
            pub_key,
            key_params,
            Digest::try_from(digest_values).unwrap(),
            signature,
        )
        .unwrap_err()
    {
        assert_eq!(error.kind(), Some(Tss2ResponseCodeKind::Signature));
    } else {
        panic!("The signature verification should have failed with an invalid signature error.");
    }
}

#[test]
fn full_test() {
    let mut ctx = create_ctx();
    for _ in 0..4 {
        let key_params = KeyParams::Rsa {
            size: RsaKeyBits::Rsa2048,
            scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                .expect("Failed to create RSA scheme"),
            pub_exponent: RsaExponent::default(),
        };
        let (key, auth) = ctx.create_key(key_params, 16).unwrap();
        let signature = ctx
            .sign(
                key.clone(),
                key_params,
                auth,
                Digest::try_from(HASH.to_vec()).unwrap(),
            )
            .unwrap();
        let pub_key = ctx
            .load_external_public_key(key.public().clone(), key_params)
            .unwrap();
        let _ = ctx
            .verify_signature(
                pub_key,
                key_params,
                Digest::try_from(HASH.to_vec()).unwrap(),
                signature,
            )
            .unwrap();
    }
}

#[test]
fn create_ecc_key() {
    let mut ctx = create_ctx();
    let _ = ctx
        .create_key(
            KeyParams::Ecc {
                curve: EccCurve::NistP256,
                scheme: EccScheme::create(
                    EccSchemeAlgorithm::EcDsa,
                    Some(HashingAlgorithm::Sha256),
                    None,
                )
                .expect("Failed to create ecc scheme"),
            },
            16,
        )
        .unwrap();
}

#[test]
fn create_ecc_key_decryption_scheme() {
    let mut ctx = create_ctx();
    let _ = ctx
        .create_key(
            KeyParams::Ecc {
                curve: EccCurve::NistP256,
                scheme: EccScheme::create(
                    EccSchemeAlgorithm::EcDh,
                    Some(HashingAlgorithm::Sha256),
                    None,
                )
                .expect("Failed to create ecc scheme"),
            },
            16,
        )
        .unwrap_err();
}

#[test]
fn full_ecc_test() {
    let mut ctx = create_ctx();
    let key_params = KeyParams::Ecc {
        curve: EccCurve::NistP256,
        scheme: EccScheme::create(
            EccSchemeAlgorithm::EcDsa,
            Some(HashingAlgorithm::Sha256),
            None,
        )
        .expect("Failed to create ecc scheme"),
    };
    for _ in 0..4 {
        let (key, auth) = ctx.create_key(key_params, 16).unwrap();
        let signature = ctx
            .sign(
                key.clone(),
                key_params,
                auth,
                Digest::try_from(HASH.to_vec()).unwrap(),
            )
            .unwrap();
        let pub_key = ctx
            .load_external_public_key(key.public().clone(), key_params)
            .unwrap();
        let _ = ctx
            .verify_signature(
                pub_key,
                key_params,
                Digest::try_from(HASH.to_vec()).unwrap(),
                signature,
            )
            .unwrap();
    }
}

#[test]
fn ctx_migration_test() {
    // Create two key contexts using `Context`, one for an RSA keypair,
    // one for just the public part of the key
    let mut basic_ctx = crate::common::create_ctx_with_session();
    let mut random_digest = vec![0u8; 16];
    getrandom::fill(&mut random_digest).unwrap();
    let key_auth = Auth::try_from(random_digest).unwrap();
    let prim_key_handle = basic_ctx
        .create_primary(
            Hierarchy::Owner,
            create_restricted_decryption_rsa_public(
                SymmetricDefinitionObject::AES_256_CFB,
                RsaKeyBits::Rsa2048,
                RsaExponent::create(0).unwrap(),
            )
            .unwrap(),
            Some(key_auth.clone()),
            None,
            None,
            None,
        )
        .unwrap()
        .key_handle;

    let result = basic_ctx
        .create(
            prim_key_handle,
            crate::common::signing_key_pub(),
            Some(key_auth.clone()),
            None,
            None,
            None,
        )
        .unwrap();

    let key_handle = basic_ctx
        .load(
            prim_key_handle,
            result.out_private.clone(),
            result.out_public.clone(),
        )
        .unwrap();
    let key_context = basic_ctx.context_save(key_handle.into()).unwrap();

    let pub_key_handle = basic_ctx
        .load_external_public(result.out_public.clone(), Hierarchy::Owner)
        .unwrap();
    let pub_key_context = basic_ctx.context_save(pub_key_handle.into()).unwrap();

    // Drop the `Context` to free the comms channel to the TPM
    std::mem::drop(basic_ctx);

    // Migrate the keys and attempt to use them
    let mut ctx = create_ctx();
    let key = ctx
        .migrate_key_from_ctx(key_context, Some(key_auth.clone()))
        .unwrap();
    let pub_key = ctx
        .migrate_key_from_ctx(pub_key_context, Some(key_auth.clone()))
        .unwrap();

    let key_params = KeyParams::Rsa {
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        size: RsaKeyBits::Rsa2048,
        pub_exponent: RsaExponent::default(),
    };
    let signature = ctx
        .sign(
            key.clone(),
            key_params,
            Some(key_auth),
            Digest::try_from(HASH.to_vec()).unwrap(),
        )
        .unwrap();
    let _ = ctx
        .verify_signature(
            pub_key.clone(),
            key_params,
            Digest::try_from(HASH.to_vec()).unwrap(),
            signature,
        )
        .expect("the signature should be valid");

    // Check that the public key is identical across the migration
    if let CreateKeyResult {
        out_public: Public::Rsa { unique, .. },
        ..
    } = result
    {
        assert_eq!(
            PublicKey::Rsa(unique.value().to_vec()),
            pub_key.public().clone()
        );
        assert_eq!(
            PublicKey::Rsa(unique.value().to_vec()),
            key.public().clone()
        );
    } else {
        panic!("Got wrong type of key from TPM");
    }
}

#[test]
fn activate_credential() {
    // create a Transient key context, generate a key and
    // obtain the Make Credential parameters
    let mut ctx = create_ctx();
    let params = KeyParams::Ecc {
        curve: EccCurve::NistP256,
        scheme: EccScheme::create(
            EccSchemeAlgorithm::EcDsa,
            Some(HashingAlgorithm::Sha256),
            None,
        )
        .expect("Failed to create ecc scheme"),
    };
    let (material, auth) = ctx.create_key(params, 16).unwrap();
    let obj = ObjectWrapper {
        material,
        params,
        auth,
    };
    let make_cred_params = ctx.get_make_cred_params(obj.clone(), None).unwrap();

    drop(ctx);

    // create a normal Context and make the credential
    let mut basic_ctx = crate::common::create_ctx_with_session();

    // the public part of the EK is used, so we retrieve the parameters
    let key_pub =
        ek::create_ek_public_from_default_template(AsymmetricAlgorithm::Rsa, None).unwrap();
    let key_pub = if let Public::Rsa {
        object_attributes,
        name_hashing_algorithm,
        auth_policy,
        parameters,
        ..
    } = key_pub
    {
        Public::Rsa {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique: if let PublicKey::Rsa(val) = make_cred_params.attesting_key_pub {
                PublicKeyRsa::try_from(val).unwrap()
            } else {
                panic!("Wrong public key type");
            },
        }
    } else {
        panic!("Wrong Public type");
    };
    let pub_handle = basic_ctx
        .load_external_public(key_pub, Hierarchy::Owner)
        .unwrap();

    // Credential to expect back as proof for attestation
    let credential = vec![0x53; 16];

    let (cred, secret) = basic_ctx
        .make_credential(
            pub_handle,
            credential.clone().try_into().unwrap(),
            make_cred_params.name.try_into().unwrap(),
        )
        .unwrap();

    drop(basic_ctx);

    // Create a new Transient key context and activate the credential
    let mut ctx = create_ctx();
    let cred_back = ctx
        .activate_credential(obj, None, cred.value().to_vec(), secret.value().to_vec())
        .unwrap();

    assert_eq!(cred_back, credential);
}

#[test]
fn activate_credential_2() {
    // create a Transient key context, generate a key and
    // obtain the Make Credential parameters
    let mut ctx = create_ctx();
    let params = KeyParams::Ecc {
        curve: EccCurve::NistP256,
        scheme: EccScheme::create(
            EccSchemeAlgorithm::EcDsa,
            Some(HashingAlgorithm::Sha256),
            None,
        )
        .expect("Failed to create ecc scheme"),
    };
    let (material, auth) = ctx.create_key(params, 16).unwrap();
    let obj = ObjectWrapper {
        material,
        params,
        auth,
    };
    let make_cred_params = ctx.get_make_cred_params(obj.clone(), None).unwrap();

    drop(ctx);

    // create a normal Context and make the credential
    let mut basic_ctx = crate::common::create_ctx_with_session();

    // the public part of the EK is used, so we retrieve the parameters
    let key_pub = ek::create_ek_public_from_default_template_2(
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        None,
    )
    .unwrap();
    let key_pub = if let Public::Rsa {
        object_attributes,
        name_hashing_algorithm,
        auth_policy,
        parameters,
        ..
    } = key_pub
    {
        Public::Rsa {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique: if let PublicKey::Rsa(val) = make_cred_params.attesting_key_pub {
                PublicKeyRsa::try_from(val).unwrap()
            } else {
                panic!("Wrong public key type");
            },
        }
    } else {
        panic!("Wrong Public type");
    };
    let pub_handle = basic_ctx
        .load_external_public(key_pub, Hierarchy::Owner)
        .unwrap();

    // Credential to expect back as proof for attestation
    let credential = vec![0x53; 16];

    let (cred, secret) = basic_ctx
        .make_credential(
            pub_handle,
            credential.clone().try_into().unwrap(),
            make_cred_params.name.try_into().unwrap(),
        )
        .unwrap();

    drop(basic_ctx);

    // Create a new Transient key context and activate the credential
    let mut ctx = create_ctx();
    let cred_back = ctx
        .activate_credential(obj, None, cred.value().to_vec(), secret.value().to_vec())
        .unwrap();

    assert_eq!(cred_back, credential);
}

#[test]
fn make_cred_params_name() {
    // create a Transient key context, generate a key and
    // obtain the Make Credential parameters
    let mut ctx = create_ctx();
    let params = KeyParams::Ecc {
        curve: EccCurve::NistP256,
        scheme: EccScheme::create(
            EccSchemeAlgorithm::EcDsa,
            Some(HashingAlgorithm::Sha256),
            None,
        )
        .expect("Failed to create ecc scheme"),
    };
    let (material, auth) = ctx.create_key(params, 16).unwrap();
    let obj = ObjectWrapper {
        material,
        params,
        auth,
    };
    let make_cred_params = ctx.get_make_cred_params(obj, None).unwrap();

    // Verify that the name provided in the parameters is
    // consistent with the public buffer
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(make_cred_params.public);
    let hash = hasher.finalize();
    // The first 2 bytes of the name represent the hash algorithm used
    assert_eq!(make_cred_params.name[2..], hash[..]);
}

#[test]
fn activate_credential_wrong_key() {
    // create a Transient key context, generate two keys and
    // obtain the Make Credential parameters for the first one
    let mut ctx = create_ctx();
    let params = KeyParams::Ecc {
        curve: EccCurve::NistP256,
        scheme: EccScheme::create(
            EccSchemeAlgorithm::EcDsa,
            Some(HashingAlgorithm::Sha256),
            None,
        )
        .expect("Failed to create ecc scheme"),
    };
    // "Good" key (for which the credential will be generated)
    let (material, auth) = ctx.create_key(params, 16).unwrap();
    let obj = ObjectWrapper {
        material,
        params,
        auth,
    };
    let make_cred_params = ctx.get_make_cred_params(obj, None).unwrap();

    // "Wrong" key (which will be used instead of the good key in attestation)
    let (material, auth) = ctx.create_key(params, 16).unwrap();
    let wrong_obj = ObjectWrapper {
        material,
        params,
        auth,
    };

    drop(ctx);

    // create a normal Context and make the credential
    let mut basic_ctx = crate::common::create_ctx_with_session();

    // the public part of the EK is used, so we retrieve the parameters
    let key_pub =
        ek::create_ek_public_from_default_template(AsymmetricAlgorithm::Rsa, None).unwrap();
    let key_pub = if let Public::Rsa {
        object_attributes,
        name_hashing_algorithm,
        auth_policy,
        parameters,
        ..
    } = key_pub
    {
        Public::Rsa {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique: if let PublicKey::Rsa(val) = make_cred_params.attesting_key_pub {
                PublicKeyRsa::try_from(val).unwrap()
            } else {
                panic!("Wrong public key type");
            },
        }
    } else {
        panic!("Wrong Public type");
    };
    let pub_handle = basic_ctx
        .load_external_public(key_pub, Hierarchy::Owner)
        .unwrap();

    // Credential to expect back as proof for attestation
    let credential = vec![0x53; 16];

    let (cred, secret) = basic_ctx
        .make_credential(
            pub_handle,
            credential.try_into().unwrap(),
            make_cred_params.name.try_into().unwrap(),
        )
        .unwrap();

    drop(basic_ctx);

    // Create a new Transient key context and activate the credential
    // Validation fails within the TPM because the credential HMAC is
    // associated with a different object (so the integrity check fails).
    let mut ctx = create_ctx();
    let e = ctx
        .activate_credential(
            wrong_obj,
            None,
            cred.value().to_vec(),
            secret.value().to_vec(),
        )
        .unwrap_err();
    if let Error::Tss2Error(e) = e {
        assert_eq!(e.kind(), Some(Tss2ResponseCodeKind::Integrity));
    } else {
        panic!("Got crate error ({}) when expecting an error from TPM.", e);
    }
}

#[test]
fn activate_credential_wrong_key_2() {
    // create a Transient key context, generate two keys and
    // obtain the Make Credential parameters for the first one
    let mut ctx = create_ctx();
    let params = KeyParams::Ecc {
        curve: EccCurve::NistP256,
        scheme: EccScheme::create(
            EccSchemeAlgorithm::EcDsa,
            Some(HashingAlgorithm::Sha256),
            None,
        )
        .expect("Failed to create ecc scheme"),
    };
    // "Good" key (for which the credential will be generated)
    let (material, auth) = ctx.create_key(params, 16).unwrap();
    let obj = ObjectWrapper {
        material,
        params,
        auth,
    };
    let make_cred_params = ctx.get_make_cred_params(obj, None).unwrap();

    // "Wrong" key (which will be used instead of the good key in attestation)
    let (material, auth) = ctx.create_key(params, 16).unwrap();
    let wrong_obj = ObjectWrapper {
        material,
        params,
        auth,
    };

    drop(ctx);

    // create a normal Context and make the credential
    let mut basic_ctx = crate::common::create_ctx_with_session();

    // the public part of the EK is used, so we retrieve the parameters
    let key_pub = ek::create_ek_public_from_default_template_2(
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        None,
    )
    .unwrap();
    let key_pub = if let Public::Rsa {
        object_attributes,
        name_hashing_algorithm,
        auth_policy,
        parameters,
        ..
    } = key_pub
    {
        Public::Rsa {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique: if let PublicKey::Rsa(val) = make_cred_params.attesting_key_pub {
                PublicKeyRsa::try_from(val).unwrap()
            } else {
                panic!("Wrong public key type");
            },
        }
    } else {
        panic!("Wrong Public type");
    };
    let pub_handle = basic_ctx
        .load_external_public(key_pub, Hierarchy::Owner)
        .unwrap();

    // Credential to expect back as proof for attestation
    let credential = vec![0x53; 16];

    let (cred, secret) = basic_ctx
        .make_credential(
            pub_handle,
            credential.try_into().unwrap(),
            make_cred_params.name.try_into().unwrap(),
        )
        .unwrap();

    drop(basic_ctx);

    // Create a new Transient key context and activate the credential
    // Validation fails within the TPM because the credential HMAC is
    // associated with a different object (so the integrity check fails).
    let mut ctx = create_ctx();
    let e = ctx
        .activate_credential(
            wrong_obj,
            None,
            cred.value().to_vec(),
            secret.value().to_vec(),
        )
        .unwrap_err();
    if let Error::Tss2Error(e) = e {
        assert_eq!(e.kind(), Some(Tss2ResponseCodeKind::Integrity));
    } else {
        panic!("Got crate error ({}) when expecting an error from TPM.", e);
    }
}

#[test]
fn activate_credential_wrong_data() {
    let mut ctx = create_ctx();
    let params = KeyParams::Ecc {
        curve: EccCurve::NistP256,
        scheme: EccScheme::create(
            EccSchemeAlgorithm::EcDsa,
            Some(HashingAlgorithm::Sha256),
            None,
        )
        .expect("Failed to create ecc scheme"),
    };
    // "Good" key (for which the credential will be generated)
    let (material, auth) = ctx.create_key(params, 16).unwrap();
    let obj = ObjectWrapper {
        material,
        params,
        auth,
    };

    // No data (essentially wrong size)
    let e = ctx
        .activate_credential(obj.clone(), None, vec![], vec![])
        .unwrap_err();
    if let Error::Tss2Error(e) = e {
        assert_eq!(e.kind(), Some(Tss2ResponseCodeKind::Size));
    } else {
        panic!("Got crate error ({}) when expecting an error from TPM.", e);
    }

    // Correct size but gibberish
    let e = ctx
        .activate_credential(obj, None, vec![0xaa; 52], vec![0x55; 256])
        .unwrap_err();
    if let Error::Tss2Error(e) = e {
        // IBM software TPM returns Value, swtpm returns Failure...
        assert!(matches!(
            e.kind(),
            Some(Tss2ResponseCodeKind::Value) | Some(Tss2ResponseCodeKind::Failure)
        ));
    } else {
        panic!("Got crate error ({}) when expecting an error from TPM.", e);
    }
}

#[test]
fn get_random_from_tkc() {
    // Check that we can convert a reference from TKC to Context
    let mut ctx = create_ctx();
    let _rand_bytes = ctx
        .as_mut()
        .execute_without_session(|ctx| ctx.get_random(16))
        .expect("Failed to get random bytes");
}
