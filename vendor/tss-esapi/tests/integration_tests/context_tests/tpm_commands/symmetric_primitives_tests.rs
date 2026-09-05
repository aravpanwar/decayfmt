// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_encrypt_decrypt_2 {
    use crate::common::create_ctx_without_session;
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        abstraction::cipher::Cipher,
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
            key_bits::RsaKeyBits,
            resource_handles::Hierarchy,
            session_handles::AuthSession,
        },
        structures::{
            Auth, InitialValue, MaxBuffer, PublicBuilder, RsaExponent, SensitiveData,
            SymmetricCipherParameters,
        },
    };
    #[test]
    fn test_encrypt_decrypt_with_aes_128_cfb_symmetric_key() {
        let mut context = create_ctx_without_session();

        context
            .tr_set_auth(Hierarchy::Owner.into(), Auth::default())
            .expect("Failed to set auth to empty for owner");

        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).expect("get_rand call failed");
        let primary_key_auth =
            Auth::try_from(random_digest).expect("Failed to create primary key auth");

        let primary_key_handle = context.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                tss_esapi::utils::create_restricted_decryption_rsa_public(
                    Cipher::aes_128_cfb()
                        .try_into()
                        .expect("Failed to convert from Cipher"),
                    RsaKeyBits::Rsa2048,
                    RsaExponent::default(),
                )
                .expect("Failed to create public for primary key"),
                Some(primary_key_auth.clone()),
                None,
                None,
                None,
            )
            .expect("Failed to create primary handle")
            .key_handle
        });

        context
            .tr_set_auth(primary_key_handle.into(), primary_key_auth)
            .expect("Failed to set auth from primary key handle.");

        let symmetric_key_object_attributes = ObjectAttributesBuilder::new()
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .with_decrypt(true)
            .build()
            .expect("Failed to create object attributes for symmetric key");

        let symmetric_key_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(symmetric_key_object_attributes)
            .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
                Cipher::aes_128_cfb()
                    .try_into()
                    .expect("Failed to create symmteric cipher parameters from cipher"),
            ))
            .with_symmetric_cipher_unique_identifier(Default::default())
            .build()
            .expect("Failed to create public for symmetric key public");

        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).expect("get_rand call failed");
        let symmetric_key_auth =
            Auth::try_from(random_digest).expect("Failed to create symmetric key auth");

        let symmetric_key_value =
            SensitiveData::try_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                .expect("Failed to create sensitive data from data");

        // if this fails with "tpm:parameter(2):inconsistent attributes" then the symmetric
        // cipher is probably not supported.
        let symmetric_key_creation_data =
            context.execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.create(
                    primary_key_handle,
                    symmetric_key_public,
                    Some(symmetric_key_auth.clone()),
                    Some(symmetric_key_value),
                    None,
                    None,
                )
                .expect("Failed to create symmetric key")
            });

        let symmetric_key_handle =
            context.execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.load(
                    primary_key_handle,
                    symmetric_key_creation_data.out_private,
                    symmetric_key_creation_data.out_public,
                )
                .expect("Failed to load symmetric key")
            });

        context
            .tr_set_auth(symmetric_key_handle.into(), symmetric_key_auth)
            .expect("Failed to set auth on symmetric key handle");

        let initial_value =
            InitialValue::try_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                .expect("Failed to create InitialValue from data");

        let data = MaxBuffer::try_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16])
            .expect("Failed to create MaxBuffer from data");

        let (encrypted_data, _) =
            context.execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.encrypt_decrypt_2(
                    symmetric_key_handle,
                    false,
                    SymmetricMode::Cfb,
                    data.clone(),
                    initial_value.clone(),
                )
                .expect("Call to encrypt_decrypt_2 failed when encrypting data")
            });

        assert_ne!(data, encrypted_data);

        let (decrypted_data, _) =
            context.execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.encrypt_decrypt_2(
                    symmetric_key_handle,
                    true,
                    SymmetricMode::Cfb,
                    encrypted_data,
                    initial_value,
                )
                .expect("Call to encrypt_decrypt_2 failed when decrypting data")
            });

        debug_assert_eq!(data, decrypted_data);
    }
}

mod test_hash {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{MaxBuffer, Ticket},
    };

    #[test]
    fn test_hash_with_sha_256() {
        let mut context = create_ctx_without_session();
        let data = "There is no spoon";
        let expected_hashed_data: [u8; 32] = [
            0x6b, 0x38, 0x4d, 0x2b, 0xfb, 0x0e, 0x0d, 0xfb, 0x64, 0x89, 0xdb, 0xf4, 0xf8, 0xe9,
            0xe5, 0x2f, 0x71, 0xee, 0xb1, 0x0d, 0x06, 0x4c, 0x56, 0x59, 0x70, 0xcd, 0xd9, 0x44,
            0x43, 0x18, 0x5d, 0xc1,
        ];
        let expected_hierarchy = Hierarchy::Owner;
        let (actual_hashed_data, ticket) = context
            .hash(
                MaxBuffer::try_from(data.as_bytes().to_vec()).unwrap(),
                HashingAlgorithm::Sha256,
                expected_hierarchy,
            )
            .unwrap();
        assert_eq!(expected_hashed_data.len(), actual_hashed_data.len());
        assert_eq!(&expected_hashed_data[..], &actual_hashed_data[..]);
        assert_eq!(ticket.hierarchy(), expected_hierarchy);
        assert_ne!(ticket.digest().len(), 0); // Should do some better checking of the digest
    }
}

mod test_hmac {
    use crate::common::create_ctx_with_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            resource_handles::Hierarchy,
        },
        structures::{KeyedHashScheme, MaxBuffer, PublicBuilder, PublicKeyedHashParameters},
    };

    #[test]
    fn test_hmac() {
        let mut context = create_ctx_with_session();

        let object_attributes = ObjectAttributesBuilder::new()
            .with_sign_encrypt(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .build()
            .expect("Failed to build object attributes");

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            ))
            .with_keyed_hash_unique_identifier(Default::default())
            .build()
            .expect("Failed to build public structure for key.");

        let key = context
            .create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
            .unwrap();

        let data = vec![1, 2, 3, 4];

        let buf = MaxBuffer::try_from(data).unwrap();
        context
            .hmac(key.key_handle.into(), buf, HashingAlgorithm::Sha256)
            .unwrap();
    }
}
