// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    abstraction::{AsymmetricAlgorithmSelection, IntoKeyCustomization, KeyCustomization},
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{AlgorithmIdentifier, SessionType},
    handles::{AuthHandle, KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{
            AsymmetricAlgorithm, EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm,
            RsaSchemeAlgorithm, SignatureSchemeAlgorithm,
        },
        session_handles::PolicySession,
    },
    structures::{
        Auth, CreateKeyResult, Digest, DigestList, EccPoint, EccScheme,
        KeyDerivationFunctionScheme, Private, Public, PublicBuilder, PublicEccParametersBuilder,
        PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
        SymmetricDefinitionObject,
    },
    Context, Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::TryFrom;

// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.5 Revision 2
// Section B.6
const POLICY_A_SHA384: [u8; 48] = [
    0x8b, 0xbf, 0x22, 0x66, 0x53, 0x7c, 0x17, 0x1c, 0xb5, 0x6e, 0x40, 0x3c, 0x4d, 0xc1, 0xd4, 0xb6,
    0x4f, 0x43, 0x26, 0x11, 0xdc, 0x38, 0x6e, 0x6f, 0x53, 0x20, 0x50, 0xc3, 0x27, 0x8c, 0x93, 0x0e,
    0x14, 0x3e, 0x8b, 0xb1, 0x13, 0x38, 0x24, 0xcc, 0xb4, 0x31, 0x05, 0x38, 0x71, 0xc6, 0xdb, 0x53,
];
const POLICY_A_SHA512: [u8; 64] = [
    0x1e, 0x3b, 0x76, 0x50, 0x2c, 0x8a, 0x14, 0x25, 0xaa, 0x0b, 0x7b, 0x3f, 0xc6, 0x46, 0xa1, 0xb0,
    0xfa, 0xe0, 0x63, 0xb0, 0x3b, 0x53, 0x68, 0xf9, 0xc4, 0xcd, 0xde, 0xca, 0xff, 0x08, 0x91, 0xdd,
    0x68, 0x2b, 0xac, 0x1a, 0x85, 0xd4, 0xd8, 0x32, 0xb7, 0x81, 0xea, 0x45, 0x19, 0x15, 0xde, 0x5f,
    0xc5, 0xbf, 0x0d, 0xc4, 0xa1, 0x91, 0x7c, 0xd4, 0x2f, 0xa0, 0x41, 0xe3, 0xf9, 0x98, 0xe0, 0xee,
];
const POLICY_A_SM3_256: [u8; 32] = [
    0xc6, 0x7f, 0x7d, 0x35, 0xf6, 0x6f, 0x3b, 0xec, 0x13, 0xc8, 0x9f, 0xe8, 0x98, 0x92, 0x1c, 0x65,
    0x1b, 0x0c, 0xb5, 0xa3, 0x8a, 0x92, 0x69, 0x0a, 0x62, 0xa4, 0x3c, 0x00, 0x12, 0xe4, 0xfb, 0x8b,
];
const POLICY_C_SHA384: [u8; 48] = [
    0xd6, 0x03, 0x2c, 0xe6, 0x1f, 0x2f, 0xb3, 0xc2, 0x40, 0xeb, 0x3c, 0xf6, 0xa3, 0x32, 0x37, 0xef,
    0x2b, 0x6a, 0x16, 0xf4, 0x29, 0x3c, 0x22, 0xb4, 0x55, 0xe2, 0x61, 0xcf, 0xfd, 0x21, 0x7a, 0xd5,
    0xb4, 0x94, 0x7c, 0x2d, 0x73, 0xe6, 0x30, 0x05, 0xee, 0xd2, 0xdc, 0x2b, 0x35, 0x93, 0xd1, 0x65,
];
const POLICY_C_SHA512: [u8; 64] = [
    0x58, 0x9e, 0xe1, 0xe1, 0x46, 0x54, 0x47, 0x16, 0xe8, 0xde, 0xaf, 0xe6, 0xdb, 0x24, 0x7b, 0x01,
    0xb8, 0x1e, 0x9f, 0x9c, 0x7d, 0xd1, 0x6b, 0x81, 0x4a, 0xa1, 0x59, 0x13, 0x87, 0x49, 0x10, 0x5f,
    0xba, 0x53, 0x88, 0xdd, 0x1d, 0xea, 0x70, 0x2f, 0x35, 0x24, 0x0c, 0x18, 0x49, 0x33, 0x12, 0x1e,
    0x2c, 0x61, 0xb8, 0xf5, 0x0d, 0x3e, 0xf9, 0x13, 0x93, 0xa4, 0x9a, 0x38, 0xc3, 0xf7, 0x3f, 0xc8,
];
const POLICY_C_SM3_256: [u8; 32] = [
    0x2d, 0x4e, 0x81, 0x57, 0x8c, 0x35, 0x31, 0xd9, 0xbd, 0x1c, 0xdd, 0x7d, 0x02, 0xba, 0x29, 0x8d,
    0x56, 0x99, 0xa3, 0xe3, 0x9f, 0xc3, 0x55, 0x1b, 0xfe, 0xff, 0xcf, 0x13, 0x2b, 0x49, 0xe1, 0x1d,
];

/// Creates a Public object for an AK key.
fn create_ak_public<IKC: IntoKeyCustomization>(
    key_alg: AsymmetricAlgorithmSelection,
    hash_alg: HashingAlgorithm,
    sign_alg: SignatureSchemeAlgorithm,
    key_customization: IKC,
) -> Result<Public> {
    let key_customization = key_customization.into_key_customization();

    let obj_attrs_builder = ObjectAttributesBuilder::new()
        .with_restricted(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true);

    let obj_attrs = if let Some(ref k) = key_customization {
        k.attributes(obj_attrs_builder)
    } else {
        obj_attrs_builder
    }
    .build()?;

    let key_builder = match key_alg {
        AsymmetricAlgorithmSelection::Rsa(key_bits) => PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(hash_alg)
            .with_object_attributes(obj_attrs)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_scheme(RsaScheme::create(
                        RsaSchemeAlgorithm::try_from(AlgorithmIdentifier::from(sign_alg))?,
                        Some(hash_alg),
                    )?)
                    .with_key_bits(key_bits)
                    .with_exponent(RsaExponent::default())
                    .with_is_signing_key(obj_attrs.sign_encrypt())
                    .with_is_decryption_key(obj_attrs.decrypt())
                    .with_restricted(obj_attrs.restricted())
                    .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default()),
        AsymmetricAlgorithmSelection::Ecc(ecc_curve) => PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(hash_alg)
            .with_object_attributes(obj_attrs)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_symmetric(SymmetricDefinitionObject::Null)
                    .with_ecc_scheme(EccScheme::create(
                        EccSchemeAlgorithm::try_from(AlgorithmIdentifier::from(sign_alg))?,
                        Some(hash_alg),
                        if sign_alg == SignatureSchemeAlgorithm::EcDaa {
                            Some(0)
                        } else {
                            None
                        },
                    )?)
                    .with_curve(ecc_curve)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()?,
            )
            .with_ecc_unique_identifier(EccPoint::default()),
    };

    let key_builder = if let Some(ref k) = key_customization {
        k.template(key_builder)
    } else {
        key_builder
    };

    key_builder.build()
}

/// Extracts the hashing and symmetric algorithm from parent and constructs the correct DigestList for OR policy
fn session_config(
    context: &mut Context,
    parent: KeyHandle,
) -> Result<(HashingAlgorithm, SymmetricDefinitionObject, DigestList)> {
    let (parent_public, _, _) = context.read_public(parent)?;
    let parent_hash_alg = parent_public.name_hashing_algorithm();
    let parent_symmetric = parent_public
        .symmetric_algorithm()
        .ok_or_else(|| Error::local_error(WrapperErrorKind::InvalidParam))?;

    let mut policy_digests = DigestList::new();

    match parent_hash_alg {
        HashingAlgorithm::Sha384 => {
            policy_digests.add(Digest::try_from(POLICY_A_SHA384.as_slice())?)?;
            policy_digests.add(Digest::try_from(POLICY_C_SHA384.as_slice())?)?;
        }
        HashingAlgorithm::Sha512 => {
            policy_digests.add(Digest::try_from(POLICY_A_SHA512.as_slice())?)?;
            policy_digests.add(Digest::try_from(POLICY_C_SHA512.as_slice())?)?;
        }
        HashingAlgorithm::Sm3_256 => {
            policy_digests.add(Digest::try_from(POLICY_A_SM3_256.as_slice())?)?;
            policy_digests.add(Digest::try_from(POLICY_C_SM3_256.as_slice())?)?;
        }
        _ => (),
    };

    Ok((parent_hash_alg, parent_symmetric, policy_digests))
}

/// This loads an Attestation Key previously generated under the Endorsement hierarchy
pub fn load_ak(
    context: &mut Context,
    parent: KeyHandle,
    ak_auth_value: Option<Auth>,
    private: Private,
    public: Public,
) -> Result<KeyHandle> {
    let (parent_hash_alg, parent_symmetric, policy_digests) = session_config(context, parent)?;

    let policy_auth_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            parent_symmetric.into(),
            parent_hash_alg,
        )?
        .ok_or_else(|| Error::local_error(WrapperErrorKind::WrongValueFromTpm))?;

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context.tr_sess_set_attributes(
        policy_auth_session,
        session_attributes,
        session_attributes_mask,
    )?;

    let key_handle = context.execute_with_temporary_object(
        SessionHandle::from(policy_auth_session).into(),
        |ctx, _| {
            let _ = ctx.execute_with_nullauth_session(|ctx| {
                ctx.policy_secret(
                    PolicySession::try_from(policy_auth_session)?,
                    AuthHandle::Endorsement,
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    None,
                )
            })?;

            if !policy_digests.is_empty() {
                ctx.policy_or(
                    PolicySession::try_from(policy_auth_session)?,
                    policy_digests,
                )?
            }

            ctx.execute_with_session(Some(policy_auth_session), |ctx| {
                ctx.load(parent, private, public)
            })
        },
    )?;

    if let Some(ak_auth_value) = ak_auth_value {
        context.tr_set_auth(key_handle.into(), ak_auth_value)?;
    }

    Ok(key_handle)
}

/// This creates an Attestation Key in the Endorsement hierarchy.
///
/// <div class="warning">
///
/// The API of this function will be changed to that of [`create_ak_2`]
/// in the next major version.
///
/// </div>
pub fn create_ak<IKC: IntoKeyCustomization>(
    context: &mut Context,
    parent: KeyHandle,
    hash_alg: HashingAlgorithm,
    sign_alg: SignatureSchemeAlgorithm,
    ak_auth_value: Option<Auth>,
    key_customization: IKC,
) -> Result<CreateKeyResult> {
    let key_alg = AsymmetricAlgorithm::try_from(sign_alg).inspect_err(|_| {
        // sign_alg is either HMAC or Null.
        error!("Could not retrieve asymmetric algorithm for provided signature scheme");
    })?;
    create_ak_2(
        context,
        parent,
        hash_alg,
        AsymmetricAlgorithmSelection::try_from(key_alg)?,
        sign_alg,
        ak_auth_value,
        key_customization,
    )
}

/// This creates an Attestation Key in the Endorsement hierarchy.
///
/// <div class="warning">
///
/// This function will be removed in the next major version.
///
/// </div>
pub fn create_ak_2<IKC: IntoKeyCustomization>(
    context: &mut Context,
    parent: KeyHandle,
    hash_alg: HashingAlgorithm,
    key_alg: AsymmetricAlgorithmSelection,
    sign_alg: SignatureSchemeAlgorithm,
    ak_auth_value: Option<Auth>,
    key_customization: IKC,
) -> Result<CreateKeyResult> {
    let ak_pub = create_ak_public(key_alg, hash_alg, sign_alg, key_customization)?;
    let (parent_hash_alg, parent_symmetric, policy_digests) = session_config(context, parent)?;

    let policy_auth_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            parent_symmetric.into(),
            parent_hash_alg,
        )?
        .ok_or_else(|| Error::local_error(WrapperErrorKind::WrongValueFromTpm))?;

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context.tr_sess_set_attributes(
        policy_auth_session,
        session_attributes,
        session_attributes_mask,
    )?;

    context.execute_with_temporary_object(
        SessionHandle::from(policy_auth_session).into(),
        |ctx, _| {
            let _ = ctx.execute_with_nullauth_session(|ctx| {
                ctx.policy_secret(
                    PolicySession::try_from(policy_auth_session)?,
                    AuthHandle::Endorsement,
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    None,
                )
            })?;

            if !policy_digests.is_empty() {
                ctx.policy_or(
                    PolicySession::try_from(policy_auth_session)?,
                    policy_digests,
                )?
            };

            ctx.execute_with_session(Some(policy_auth_session), |ctx| {
                ctx.create(parent, ak_pub, ak_auth_value, None, None, None)
            })
        },
    )
}
