// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_verify_signature {
    use crate::common::{create_ctx_with_session, signing_key_pub, HASH};
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{Auth, Digest, PublicKeyRsa, RsaSignature, Signature, SignatureScheme},
        tss2_esys::TPMT_TK_HASHCHECK,
    };

    #[test]
    fn test_verify_signature() {
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

        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let signature = context
            .sign(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                SignatureScheme::Null,
                validation.try_into().unwrap(),
            )
            .unwrap();

        context
            .verify_signature(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .unwrap();
    }

    #[test]
    fn test_verify_wrong_signature() {
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

        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let mut signature = context
            .sign(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                SignatureScheme::Null,
                validation.try_into().unwrap(),
            )
            .unwrap();

        if let Signature::RsaSsa(rsa_signature) = &mut signature {
            let mut key_data: Vec<u8> = rsa_signature.signature().value().to_vec();
            key_data.reverse();
            *rsa_signature = RsaSignature::create(
                rsa_signature.hashing_algorithm(),
                PublicKeyRsa::try_from(key_data).expect("Failed to create oublic key rsa,"),
            )
            .expect("Failed to create signature");
        }

        assert!(context
            .verify_signature(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .is_err());
    }

    #[test]
    fn test_verify_wrong_signature_2() {
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

        let signature = Signature::RsaSsa(
            RsaSignature::create(
                HashingAlgorithm::Sha256,
                PublicKeyRsa::try_from(vec![0xab; 500])
                    .expect("Failed to create public key rsa structure"),
            )
            .expect("Failed to create RSA SSA signature"),
        );

        assert!(context
            .verify_signature(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .is_err());
    }

    #[test]
    fn test_verify_wrong_signature_3() {
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

        let signature = Signature::RsaSsa(
            RsaSignature::create(
                HashingAlgorithm::Sha256,
                PublicKeyRsa::try_from(vec![0; 0])
                    .expect("Failed to create public key rsa structure"),
            )
            .expect("Failed to create RSA SSA signature"),
        );
        assert!(context
            .verify_signature(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .is_err());
    }
}

mod test_sign {
    use crate::common::{create_ctx_with_session, signing_key_pub, HASH};
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
        interface_types::resource_handles::Hierarchy,
        structures::{Auth, Digest, SignatureScheme},
        tss2_esys::TPMT_TK_HASHCHECK,
    };

    #[test]
    fn test_sign() {
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

        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        context
            .sign(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                SignatureScheme::Null,
                validation.try_into().unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn test_sign_empty_digest() {
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

        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        context
            .sign(
                key_handle,
                Digest::try_from(Vec::<u8>::new()).unwrap(),
                SignatureScheme::Null,
                validation.try_into().unwrap(),
            )
            .unwrap_err();
    }

    #[test]
    fn test_sign_large_digest() {
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

        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        context
            .sign(
                key_handle,
                Digest::try_from([0xbb; 40].to_vec()).unwrap(),
                SignatureScheme::Null,
                validation.try_into().unwrap(),
            )
            .unwrap_err();
    }
}
