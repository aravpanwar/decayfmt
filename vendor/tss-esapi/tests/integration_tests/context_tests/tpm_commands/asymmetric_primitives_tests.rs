// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_rsa_encrypt_decrypt {
    use crate::common::{create_ctx_with_session, encryption_decryption_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::{
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, RsaDecryptAlgorithm},
            ecc::EccCurve,
            resource_handles::Hierarchy,
        },
        structures::{
            Auth, Data, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme,
            PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, RsaDecryptionScheme,
        },
    };

    #[test]
    fn test_encrypt_decrypt() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();
        let key_auth = Auth::try_from(random_digest).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                encryption_decryption_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        // let scheme = AsymSchemeUnion::RSAOAEP(HashingAlgorithm::Sha256);
        let scheme =
            RsaDecryptionScheme::create(RsaDecryptAlgorithm::Oaep, Some(HashingAlgorithm::Sha256))
                .expect("Failed to create rsa decryption scheme");

        let plaintext_bytes: Vec<u8> = vec![0x01, 0x02, 0x03];

        let plaintext = PublicKeyRsa::try_from(plaintext_bytes.clone()).unwrap();

        let ciphertext = context
            .rsa_encrypt(key_handle, plaintext, scheme, Data::default())
            .unwrap();

        assert_ne!(plaintext_bytes, ciphertext.value());

        let decrypted = context
            .rsa_decrypt(key_handle, ciphertext, scheme, Data::default())
            .unwrap();

        assert_eq!(plaintext_bytes, decrypted.value());
    }

    #[test]
    fn test_ecdh() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();
        let key_auth = Auth::try_from(random_digest).unwrap();

        let ecc_parms = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(false)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build()
            .unwrap();

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(false)
            .with_restricted(false)
            .build()
            .unwrap();

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_parms)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .unwrap();

        let key_handle = context
            .create_primary(Hierarchy::Owner, public, Some(key_auth), None, None, None)
            .unwrap()
            .key_handle;

        let (z_point, pub_point) = context.ecdh_key_gen(key_handle).unwrap();

        let param = context.ecdh_z_gen(key_handle, pub_point).unwrap();

        assert_eq!(z_point.x().value(), param.x().value());
    }
}
