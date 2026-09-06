// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_create {
    use crate::common::{create_ctx_with_session, decryption_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::resource_handles::Hierarchy, structures::Auth};

    #[test]
    fn test_create() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();
        let key_auth = Auth::try_from(random_digest).unwrap();

        let prim_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                Some(key_auth.clone()),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let _ = context
            .create(
                prim_key_handle,
                decryption_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap();
    }
}

mod test_load {
    use crate::common::{create_ctx_with_session, decryption_key_pub, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::resource_handles::Hierarchy, structures::Auth};

    #[test]
    fn test_load() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();
        let key_auth = Auth::try_from(random_digest).unwrap();

        let prim_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                Some(key_auth.clone()),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let result = context
            .create(
                prim_key_handle,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap();

        let _ = context
            .load(prim_key_handle, result.out_private, result.out_public)
            .unwrap();
    }
}

mod test_load_external_public {
    use crate::common::{create_ctx_with_session, KEY};
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
            key_bits::RsaKeyBits,
            resource_handles::Hierarchy,
        },
        structures::{Public, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme},
    };

    pub fn get_ext_rsa_pub() -> Public {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build object attributes");

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new_unrestricted_signing_key(
                    RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                        .expect("Failed to create rsa scheme"),
                    RsaKeyBits::Rsa2048,
                    Default::default(),
                )
                .build()
                .expect("Failed to create rsa parameters for public structure"),
            )
            .with_rsa_unique_identifier(
                PublicKeyRsa::try_from(&KEY[..256])
                    .expect("Failed to create Public RSA key from buffer"),
            )
            .build()
            .expect("Failed to build Public structure")
    }

    #[test]
    fn test_load_external_public() {
        let mut context = create_ctx_with_session();
        let pub_key = get_ext_rsa_pub();

        context
            .load_external_public(pub_key, Hierarchy::Owner)
            .unwrap();
    }
}

mod test_load_external {
    use crate::common::create_ctx_with_session;
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
            key_bits::RsaKeyBits,
            resource_handles::Hierarchy,
        },
        structures::{
            Public, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme, Sensitive,
        },
    };

    const KEY: [u8; 256] = [
        0xc9, 0x75, 0xf8, 0xb2, 0x30, 0xf4, 0x24, 0x6e, 0x95, 0xb1, 0x3c, 0x55, 0x0f, 0xe4, 0x48,
        0xe9, 0xac, 0x06, 0x1f, 0xa8, 0xbe, 0xa4, 0xd7, 0x1c, 0xa5, 0x5e, 0x2a, 0xbf, 0x60, 0xc2,
        0x98, 0x63, 0x6c, 0xb4, 0xe2, 0x61, 0x54, 0x31, 0xc3, 0x3e, 0x9d, 0x1a, 0x83, 0x84, 0x18,
        0x51, 0xe9, 0x8c, 0x24, 0xcf, 0xac, 0xc6, 0x0d, 0x26, 0x2c, 0x9f, 0x2b, 0xd5, 0x91, 0x98,
        0x89, 0xe3, 0x68, 0x97, 0x36, 0x02, 0xec, 0x16, 0x37, 0x24, 0x08, 0xb4, 0x77, 0xd1, 0x56,
        0x10, 0x3e, 0xf0, 0x64, 0xf6, 0x68, 0x50, 0x68, 0x31, 0xf8, 0x9b, 0x88, 0xf2, 0xc5, 0xfb,
        0xc9, 0x21, 0xd2, 0xdf, 0x93, 0x6f, 0x98, 0x94, 0x53, 0x68, 0xe5, 0x25, 0x8d, 0x8a, 0xf1,
        0xd7, 0x5b, 0xf3, 0xf9, 0xdf, 0x8c, 0x77, 0x24, 0x9e, 0x28, 0x09, 0x36, 0xf0, 0xa2, 0x93,
        0x17, 0xad, 0xbb, 0x1a, 0xd7, 0x6f, 0x25, 0x6b, 0x0c, 0xd3, 0x76, 0x7f, 0xcf, 0x3a, 0xe3,
        0x1a, 0x84, 0x57, 0x62, 0x71, 0x8a, 0x6a, 0x42, 0x94, 0x71, 0x21, 0x6a, 0x13, 0x73, 0x17,
        0x56, 0xa2, 0x38, 0xc1, 0x5e, 0x76, 0x0b, 0x67, 0x6b, 0x6e, 0xcd, 0xd3, 0xe2, 0x8a, 0x80,
        0x61, 0x6c, 0x1c, 0x60, 0x9d, 0x65, 0xbd, 0x5a, 0x4e, 0xeb, 0xa2, 0x06, 0xd6, 0xbe, 0xf5,
        0x49, 0xc1, 0x7d, 0xd9, 0x46, 0x3e, 0x9f, 0x2f, 0x92, 0xa4, 0x1a, 0x14, 0x2c, 0x1e, 0xb7,
        0x6d, 0x71, 0x29, 0x92, 0x43, 0x7b, 0x76, 0xa4, 0x8b, 0x33, 0xf3, 0xd0, 0xda, 0x7c, 0x7f,
        0x73, 0x50, 0xe2, 0xc5, 0x30, 0xad, 0x9e, 0x0f, 0x61, 0x73, 0xa0, 0xbb, 0x87, 0x1f, 0x0b,
        0x70, 0xa9, 0xa6, 0xaa, 0x31, 0x2d, 0x62, 0x2c, 0xaf, 0xea, 0x49, 0xb2, 0xce, 0x6c, 0x23,
        0x90, 0xdd, 0x29, 0x37, 0x67, 0xb1, 0xc9, 0x99, 0x3a, 0x3f, 0xa6, 0x69, 0xc9, 0x0d, 0x24,
        0x3f,
    ];
    /// prime2 a.k.a. "q"
    const PRIV_KEY: [u8; 128] = [
        0xcf, 0x7c, 0xe8, 0xa1, 0x9c, 0x47, 0xe1, 0x70, 0xbd, 0x38, 0x0a, 0xaf, 0x26, 0x5c, 0x48,
        0x94, 0x48, 0x54, 0x98, 0x07, 0xae, 0xb9, 0x5c, 0x46, 0xaf, 0x8f, 0x59, 0xc8, 0x30, 0x1b,
        0x98, 0xe3, 0x2a, 0x93, 0xb2, 0xdb, 0xab, 0x81, 0xbf, 0xd2, 0xad, 0x0d, 0xb6, 0x5b, 0x57,
        0xbf, 0x98, 0xcb, 0xbc, 0x97, 0xb8, 0xc3, 0xa4, 0xb0, 0xc9, 0xf1, 0x05, 0x46, 0xed, 0x06,
        0xdf, 0xdc, 0x58, 0xf4, 0xe0, 0x23, 0x15, 0x77, 0x25, 0x7b, 0x46, 0x6f, 0xea, 0x0c, 0xeb,
        0xa5, 0x49, 0x53, 0x1d, 0xa0, 0x2e, 0x3a, 0x7e, 0x8e, 0x8d, 0xec, 0xdd, 0xa6, 0x07, 0x95,
        0x40, 0xab, 0x3e, 0x10, 0x9b, 0x07, 0xce, 0xe9, 0xf3, 0xdb, 0x99, 0xb7, 0x52, 0xab, 0xa6,
        0x22, 0x43, 0x70, 0xc2, 0x2c, 0xdc, 0x98, 0x4e, 0x05, 0x62, 0xdf, 0xe4, 0x6a, 0xba, 0xbd,
        0x28, 0x4c, 0xbe, 0xbd, 0xb9, 0x80, 0x54, 0xed,
    ];

    pub fn get_ext_rsa_priv() -> Sensitive {
        Sensitive::Rsa {
            sensitive: PRIV_KEY.to_vec().try_into().unwrap(),
            auth_value: Default::default(),
            seed_value: Default::default(),
        }
    }

    pub fn get_ext_rsa_pub() -> Public {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build object attributes");

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new_unrestricted_signing_key(
                    RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                        .expect("Failed to create rsa scheme"),
                    RsaKeyBits::Rsa2048,
                    Default::default(),
                )
                .build()
                .expect("Failed to create rsa parameters for public structure"),
            )
            .with_rsa_unique_identifier(
                PublicKeyRsa::try_from(&KEY[..])
                    .expect("Failed to create Public RSA key from buffer"),
            )
            .build()
            .expect("Failed to build Public structure")
    }

    #[test]
    fn test_load_external() {
        let mut context = create_ctx_with_session();
        let pub_key = get_ext_rsa_pub();
        let priv_key = get_ext_rsa_priv();

        let key_handle = context
            .load_external(priv_key, pub_key, Hierarchy::Null)
            .unwrap();
        context.flush_context(key_handle.into()).unwrap();
    }
}

mod test_read_public {
    use crate::common::{create_ctx_with_session, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::resource_handles::Hierarchy, structures::Auth};

    #[test]
    fn test_read_public() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();
        let key_auth = Auth::try_from(random_digest).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;
        let _ = context.read_public(key_handle).unwrap();
    }
}

mod test_make_credential {
    use crate::common::{create_ctx_with_session, decryption_key_pub};
    use std::convert::TryInto;
    use tss_esapi::interface_types::resource_handles::Hierarchy;

    #[test]
    fn test_make_credential() {
        let mut context = create_ctx_with_session();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let (_, key_name, _) = context.read_public(key_handle).unwrap();

        let cred = vec![1, 2, 3, 4, 5];

        context
            .execute_without_session(|ctx| {
                ctx.make_credential(key_handle, cred.try_into().unwrap(), key_name)
            })
            .unwrap();
    }
}

mod test_activate_credential {
    use crate::common::{create_ctx_with_session, decryption_key_pub};
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{Digest, SymmetricDefinition},
    };
    #[test]
    fn test_make_activate_credential() {
        let mut context = create_ctx_with_session();

        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

        let session_1 = context
            .execute_without_session(|ctx| {
                ctx.start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Hmac,
                    SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )
            })
            .expect("session_1: Call to start_auth_session failed.")
            .expect("session_1: The auth session returned was NONE");
        context
            .tr_sess_set_attributes(session_1, session_attributes, session_attributes_mask)
            .expect("Call to tr_sess_set_attributes failed");
        let session_2 = context
            .execute_without_session(|ctx| {
                ctx.start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Hmac,
                    SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )
            })
            .expect("session_2: Call to start_auth_session failed.")
            .expect("session_2: The auth session returned was NONE");
        context
            .tr_sess_set_attributes(session_2, session_attributes, session_attributes_mask)
            .unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let (_, key_name, _) = context
            .read_public(key_handle)
            .expect("Call to read_public failed");

        let cred = vec![1, 2, 3, 4, 5];

        let (credential_blob, secret) = context
            .execute_without_session(|ctx| {
                ctx.make_credential(key_handle, cred.try_into().unwrap(), key_name)
            })
            .expect("Call to make_credential failed");

        context.set_sessions((Some(session_1), Some(session_2), None));

        let decrypted = context
            .activate_credential(key_handle, key_handle, credential_blob, secret)
            .expect("Call to active_credential failed");

        let expected =
            Digest::try_from(vec![1, 2, 3, 4, 5]).expect("Failed to create digest for expected");

        assert_eq!(expected, decrypted);
    }
}

mod test_unseal {
    use crate::common::{create_ctx_with_session, create_public_sealed_object, decryption_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::resource_handles::Hierarchy, structures::SensitiveData};

    #[test]
    fn unseal() {
        let testbytes: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x42];

        let mut context = create_ctx_with_session();

        let key_handle_seal = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;
        let key_handle_unseal = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let key_pub = create_public_sealed_object();
        let result = context
            .create(
                key_handle_seal,
                key_pub,
                None,
                Some(SensitiveData::try_from(testbytes.to_vec()).unwrap()),
                None,
                None,
            )
            .unwrap();
        let loaded_key = context
            .load(key_handle_unseal, result.out_private, result.out_public)
            .unwrap();
        let unsealed = context.unseal(loaded_key.into()).unwrap();
        let unsealed = unsealed.value();
        assert!(unsealed == testbytes);
    }
}
