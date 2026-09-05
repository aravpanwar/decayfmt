// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::{TryFrom, TryInto};

use tss_esapi::{
    abstraction::{ak, ek, AsymmetricAlgorithmSelection, KeyCustomization},
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::AuthHandle,
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        session_handles::PolicySession,
    },
    structures::{Auth, Digest, PublicBuilder, SymmetricDefinition},
    Error, WrapperErrorKind,
};

use crate::common::create_ctx_without_session;

#[test]
fn test_create_ak_rsa_rsa() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, None).unwrap();
    ak::create_ak(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        SignatureSchemeAlgorithm::RsaPss,
        None,
        None,
    )
    .unwrap();
    context.flush_context(ek_rsa.into()).unwrap();
}

#[test]
fn test_create_ak_2_rsa_rsa() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object_2(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        None,
    )
    .unwrap();
    ak::create_ak_2(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        SignatureSchemeAlgorithm::RsaPss,
        None,
        None,
    )
    .unwrap();
    context.flush_context(ek_rsa.into()).unwrap();
}

#[test]
fn test_create_ak_2_rsa_rsa_3072() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object_2(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa3072),
        None,
    )
    .unwrap();
    ak::create_ak_2(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha384,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa3072),
        SignatureSchemeAlgorithm::RsaPss,
        None,
        None,
    )
    .unwrap();
    context.flush_context(ek_rsa.into()).unwrap();
}

#[test]
fn test_create_ak_rsa_ecc() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, None).unwrap();

    if let Err(actual_error) = ak::create_ak(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        SignatureSchemeAlgorithm::Sm2,
        None,
        None,
    ) {
        let expected_error = Error::WrapperError(WrapperErrorKind::InconsistentParams);
        assert_eq!(expected_error, actual_error);
    } else {
        // We can't use unwrap_err because that requires Debug on the T(=CreateKeyResult).
        panic!("Should not be possible to create an AK with a parent that have an unsupported or incompatible scheme.");
    }
}

#[test]
fn test_create_ak_2_rsa_ecc() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object_2(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        None,
    )
    .unwrap();

    if let Err(actual_error) = ak::create_ak_2(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
        SignatureSchemeAlgorithm::Sm2,
        None,
        None,
    ) {
        let expected_error = Error::WrapperError(WrapperErrorKind::InconsistentParams);
        assert_eq!(expected_error, actual_error);
    } else {
        // We can't use unwrap_err because that requires Debug on the T(=CreateKeyResult).
        panic!("Should not be possible to create an AK with a parent that have an unsupported or incompatible scheme.");
    }
}

#[test]
fn test_create_ak_ecc_ecc() {
    let mut context = create_ctx_without_session();

    let ek_ecc = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Ecc, None).unwrap();

    let ak_res = ak::create_ak(
        &mut context,
        ek_ecc,
        HashingAlgorithm::Sha384,
        SignatureSchemeAlgorithm::EcDsa,
        None,
        None,
    )
    .unwrap();

    let ak_ecc = ak::load_ak(
        &mut context,
        ek_ecc,
        None,
        ak_res.out_private,
        ak_res.out_public,
    )
    .unwrap();

    context.flush_context(ek_ecc.into()).unwrap();
    context.flush_context(ak_ecc.into()).unwrap();
}

#[test]
fn test_create_ak_2_ecc_ecc() {
    let mut context = create_ctx_without_session();

    let ek_ecc = ek::create_ek_object_2(
        &mut context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384),
        None,
    )
    .unwrap();

    let ak_res = ak::create_ak_2(
        &mut context,
        ek_ecc,
        HashingAlgorithm::Sha384,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384),
        SignatureSchemeAlgorithm::EcDsa,
        None,
        None,
    )
    .unwrap();

    let ak_ecc = ak::load_ak(
        &mut context,
        ek_ecc,
        None,
        ak_res.out_private,
        ak_res.out_public,
    )
    .unwrap();

    context.flush_context(ek_ecc.into()).unwrap();
    context.flush_context(ak_ecc.into()).unwrap();
}

#[test]
fn test_create_ak_ecdaa() {
    let mut context = create_ctx_without_session();

    let ek_ecc = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Ecc, None).unwrap();
    ak::create_ak(
        &mut context,
        ek_ecc,
        HashingAlgorithm::Sha256,
        SignatureSchemeAlgorithm::EcDaa,
        None,
        None,
    )
    .unwrap();
    context.flush_context(ek_ecc.into()).unwrap();
}

#[test]
fn test_create_ak_2_ecdaa() {
    let mut context = create_ctx_without_session();

    let ek_ecc = ek::create_ek_object_2(
        &mut context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384),
        None,
    )
    .unwrap();
    ak::create_ak_2(
        &mut context,
        ek_ecc,
        HashingAlgorithm::Sha256,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::BnP256),
        SignatureSchemeAlgorithm::EcDaa,
        None,
        None,
    )
    .unwrap();
    context.flush_context(ek_ecc.into()).unwrap();
}

#[test]
fn test_create_and_use_ak() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, None).unwrap();
    let ak_auth = Auth::try_from(vec![0x1, 0x2, 0x42]).unwrap();
    let att_key = ak::create_ak(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        SignatureSchemeAlgorithm::RsaPss,
        Some(ak_auth.clone()),
        None,
    )
    .unwrap();

    let loaded_ak = ak::load_ak(
        &mut context,
        ek_rsa,
        Some(ak_auth),
        att_key.out_private,
        att_key.out_public,
    )
    .unwrap();

    let (_, key_name, _) = context.read_public(loaded_ak).unwrap();
    let cred = vec![1, 2, 3, 4, 5];
    let expected = Digest::try_from(vec![1, 2, 3, 4, 5]).unwrap();

    let (session_aastributes, session_attributes_mask) = SessionAttributesBuilder::new().build();
    let session_1 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to call start_auth_session")
        .expect("Failed invalid session value");
    context
        .tr_sess_set_attributes(session_1, session_aastributes, session_attributes_mask)
        .unwrap();
    let session_2 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to call start_auth_session")
        .expect("Failed invalid session value");
    context
        .tr_sess_set_attributes(session_2, session_aastributes, session_attributes_mask)
        .expect("Failed to call tr_sess_set_attributes");

    let (credential_blob, secret) = context
        .execute_without_session(|ctx| {
            ctx.make_credential(ek_rsa, cred.try_into().unwrap(), key_name)
        })
        .unwrap();

    let _ = context
        .execute_with_session(Some(session_1), |ctx| {
            ctx.policy_secret(
                PolicySession::try_from(session_2)
                    .expect("Failed to convert auth session to policy session"),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .unwrap();

    context.set_sessions((Some(session_1), Some(session_2), None));

    let decrypted = context
        .activate_credential(loaded_ak, ek_rsa, credential_blob, secret)
        .unwrap();

    assert_eq!(expected, decrypted);
}

#[test]
fn test_create_and_use_ak_2() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object_2(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        None,
    )
    .unwrap();
    let ak_auth = Auth::try_from(vec![0x1, 0x2, 0x42]).unwrap();
    let att_key = ak::create_ak_2(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        SignatureSchemeAlgorithm::RsaPss,
        Some(ak_auth.clone()),
        None,
    )
    .unwrap();

    let loaded_ak = ak::load_ak(
        &mut context,
        ek_rsa,
        Some(ak_auth),
        att_key.out_private,
        att_key.out_public,
    )
    .unwrap();

    let (_, key_name, _) = context.read_public(loaded_ak).unwrap();
    let cred = vec![1, 2, 3, 4, 5];
    let expected = Digest::try_from(vec![1, 2, 3, 4, 5]).unwrap();

    let (session_aastributes, session_attributes_mask) = SessionAttributesBuilder::new().build();
    let session_1 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to call start_auth_session")
        .expect("Failed invalid session value");
    context
        .tr_sess_set_attributes(session_1, session_aastributes, session_attributes_mask)
        .unwrap();
    let session_2 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to call start_auth_session")
        .expect("Failed invalid session value");
    context
        .tr_sess_set_attributes(session_2, session_aastributes, session_attributes_mask)
        .expect("Failed to call tr_sess_set_attributes");

    let (credential_blob, secret) = context
        .execute_without_session(|ctx| {
            ctx.make_credential(ek_rsa, cred.try_into().unwrap(), key_name)
        })
        .unwrap();

    let _ = context
        .execute_with_session(Some(session_1), |ctx| {
            ctx.policy_secret(
                PolicySession::try_from(session_2)
                    .expect("Failed to convert auth session to policy session"),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .unwrap();

    context.set_sessions((Some(session_1), Some(session_2), None));

    let decrypted = context
        .activate_credential(loaded_ak, ek_rsa, credential_blob, secret)
        .unwrap();

    assert_eq!(expected, decrypted);

    context.flush_context(ek_rsa.into()).unwrap();
    context.flush_context(loaded_ak.into()).unwrap();
}

#[test]
fn test_create_custom_ak() {
    struct CustomizeKey;
    impl KeyCustomization for &CustomizeKey {
        fn attributes(
            &self,
            attributes_builder: ObjectAttributesBuilder,
        ) -> ObjectAttributesBuilder {
            attributes_builder.with_st_clear(true)
        }

        fn template(&self, template_builder: PublicBuilder) -> PublicBuilder {
            template_builder.with_name_hashing_algorithm(HashingAlgorithm::Sha1)
        }
    }
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, None).unwrap();
    let ak_auth = Auth::try_from(vec![0x1, 0x2, 0x42]).unwrap();
    // Without customization, no st clear
    let att_key_without = ak::create_ak(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        SignatureSchemeAlgorithm::RsaPss,
        Some(ak_auth.clone()),
        None,
    )
    .unwrap();

    assert!(
        !att_key_without.out_public.object_attributes().st_clear(),
        "ST Clear was set"
    );

    // With a customization, we get a new attribute
    let att_key = ak::create_ak(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        SignatureSchemeAlgorithm::RsaPss,
        Some(ak_auth),
        &CustomizeKey,
    )
    .unwrap();

    assert_eq!(
        att_key.out_public.object_attributes().0 & tss_esapi::constants::tss::TPMA_OBJECT_STCLEAR,
        tss_esapi::constants::tss::TPMA_OBJECT_STCLEAR
    );
    assert_eq!(
        att_key.out_public.object_attributes().0,
        att_key_without.out_public.object_attributes().0
            | tss_esapi::constants::tss::TPMA_OBJECT_STCLEAR
    );

    assert_eq!(
        att_key.out_public.name_hashing_algorithm(),
        HashingAlgorithm::Sha1,
    );
}

#[test]
fn test_create_custom_ak_2() {
    struct CustomizeKey;
    impl KeyCustomization for &CustomizeKey {
        fn attributes(
            &self,
            attributes_builder: ObjectAttributesBuilder,
        ) -> ObjectAttributesBuilder {
            attributes_builder.with_st_clear(true)
        }

        fn template(&self, template_builder: PublicBuilder) -> PublicBuilder {
            template_builder.with_name_hashing_algorithm(HashingAlgorithm::Sha1)
        }
    }
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object_2(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        None,
    )
    .unwrap();
    let ak_auth = Auth::try_from(vec![0x1, 0x2, 0x42]).unwrap();
    // Without customization, no st clear
    let att_key_without = ak::create_ak_2(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        SignatureSchemeAlgorithm::RsaPss,
        Some(ak_auth.clone()),
        None,
    )
    .unwrap();

    assert!(
        !att_key_without.out_public.object_attributes().st_clear(),
        "ST Clear was set"
    );

    // With a customization, we get a new attribute
    let att_key = ak::create_ak_2(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        SignatureSchemeAlgorithm::RsaPss,
        Some(ak_auth),
        &CustomizeKey,
    )
    .unwrap();

    assert_eq!(
        att_key.out_public.object_attributes().0 & tss_esapi::constants::tss::TPMA_OBJECT_STCLEAR,
        tss_esapi::constants::tss::TPMA_OBJECT_STCLEAR
    );
    assert_eq!(
        att_key.out_public.object_attributes().0,
        att_key_without.out_public.object_attributes().0
            | tss_esapi::constants::tss::TPMA_OBJECT_STCLEAR
    );

    assert_eq!(
        att_key.out_public.name_hashing_algorithm(),
        HashingAlgorithm::Sha1,
    );
}
