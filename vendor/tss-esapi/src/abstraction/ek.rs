// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    abstraction::{nv, AsymmetricAlgorithmSelection, IntoKeyCustomization, KeyCustomization},
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, NvIndexTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, NvAuth},
    },
    structures::{
        Digest, EccParameter, EccPoint, EccScheme, KeyDerivationFunctionScheme, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
        RsaExponent, RsaScheme, SymmetricDefinitionObject,
    },
    Context, Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
// Section 2.2.1.4 (Low Range) for Windows compatibility
const RSA_2048_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c00002;
const ECC_P256_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c0000a;

// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
// Section 2.2.1.5 (High Range)
const ECC_P384_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c00016;
const ECC_P521_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c00018;
const ECC_P256_SM2_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c0001a;
const RSA_3072_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c0001c;
const RSA_4096_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c0001e;

// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.5 Revision 2
// Section B.3 and B.4
const AUTH_POLICY_A_SHA256: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];
const AUTH_POLICY_B_SHA384: [u8; 48] = [
    0xb2, 0x6e, 0x7d, 0x28, 0xd1, 0x1a, 0x50, 0xbc, 0x53, 0xd8, 0x82, 0xbc, 0xf5, 0xfd, 0x3a, 0x1a,
    0x07, 0x41, 0x48, 0xbb, 0x35, 0xd3, 0xb4, 0xe4, 0xcb, 0x1c, 0x0a, 0xd9, 0xbd, 0xe4, 0x19, 0xca,
    0xcb, 0x47, 0xba, 0x09, 0x69, 0x96, 0x46, 0x15, 0x0f, 0x9f, 0xc0, 0x00, 0xf3, 0xf8, 0x0e, 0x12,
];
const AUTH_POLICY_B_SHA512: [u8; 64] = [
    0xb8, 0x22, 0x1c, 0xa6, 0x9e, 0x85, 0x50, 0xa4, 0x91, 0x4d, 0xe3, 0xfa, 0xa6, 0xa1, 0x8c, 0x07,
    0x2c, 0xc0, 0x12, 0x08, 0x07, 0x3a, 0x92, 0x8d, 0x5d, 0x66, 0xd5, 0x9e, 0xf7, 0x9e, 0x49, 0xa4,
    0x29, 0xc4, 0x1a, 0x6b, 0x26, 0x95, 0x71, 0xd5, 0x7e, 0xdb, 0x25, 0xfb, 0xdb, 0x18, 0x38, 0x42,
    0x56, 0x08, 0xb4, 0x13, 0xcd, 0x61, 0x6a, 0x5f, 0x6d, 0xb5, 0xb6, 0x07, 0x1a, 0xf9, 0x9b, 0xea,
];
const AUTH_POLICY_B_SM3_256: [u8; 32] = [
    0x16, 0x78, 0x60, 0xa3, 0x5f, 0x2c, 0x5c, 0x35, 0x67, 0xf9, 0xc9, 0x27, 0xac, 0x56, 0xc0, 0x32,
    0xf3, 0xb3, 0xa6, 0x46, 0x2f, 0x8d, 0x03, 0x79, 0x98, 0xe7, 0xa1, 0x0f, 0x77, 0xfa, 0x45, 0x4a,
];

/// Get the [`Public`] representing a default Endorsement Key
///
/// **Note**: This only works for key algorithms specified in TCG EK Credential Profile for TPM Family 2.0.
///
/// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
/// Appendix B.3.3 and B.3.4
///
/// <div class="warning">
///
/// The API of this function will be changed to that of [`create_ek_public_from_default_template_2`]
/// in the next major version.
///
/// </div>
pub fn create_ek_public_from_default_template<IKC: IntoKeyCustomization>(
    alg: AsymmetricAlgorithm,
    key_customization: IKC,
) -> Result<Public> {
    create_ek_public_from_default_template_2(
        AsymmetricAlgorithmSelection::try_from(alg)?,
        key_customization,
    )
}

/// Get the [`Public`] representing a default Endorsement Key
///
/// **Note**: This only works for key algorithms specified in TCG EK Credential Profile for TPM Family 2.0.
///
/// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
/// Appendix B.3.3 and B.3.4
///
/// <div class="warning">
///
/// This function will be removed in the next major version.
///
/// </div>
pub fn create_ek_public_from_default_template_2<IKC: IntoKeyCustomization>(
    alg: AsymmetricAlgorithmSelection,
    key_customization: IKC,
) -> Result<Public> {
    let key_customization = key_customization.into_key_customization();

    // user_with_auth is not set for the lower profiles (RSA 2048 and ECC P256)
    let user_with_auth = !matches!(
        alg,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048)
            | AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256)
    );

    let obj_attrs_builder = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_st_clear(false)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(user_with_auth)
        .with_admin_with_policy(true)
        .with_no_da(false)
        .with_encrypted_duplication(false)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false);

    let obj_attrs = if let Some(ref k) = key_customization {
        k.attributes(obj_attrs_builder)
    } else {
        obj_attrs_builder
    }
    .build()?;

    let key_builder = match alg {
        AsymmetricAlgorithmSelection::Rsa(key_bits) => {
            let (hash_alg, auth_policy, symmetric, unique) = match key_bits {
                RsaKeyBits::Rsa2048 => (
                    HashingAlgorithm::Sha256,
                    Digest::try_from(AUTH_POLICY_A_SHA256.as_slice())?,
                    SymmetricDefinitionObject::AES_128_CFB,
                    PublicKeyRsa::new_empty_with_size(RsaKeyBits::Rsa2048),
                ),
                RsaKeyBits::Rsa3072 | RsaKeyBits::Rsa4096 => (
                    HashingAlgorithm::Sha384,
                    Digest::try_from(AUTH_POLICY_B_SHA384.as_slice())?,
                    SymmetricDefinitionObject::AES_256_CFB,
                    PublicKeyRsa::default(),
                ),
                // Other key sizes are not supported in the spec, so return a error
                _ => return Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            };

            PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(hash_alg)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(auth_policy)
                .with_rsa_parameters(
                    PublicRsaParametersBuilder::new()
                        .with_symmetric(symmetric)
                        .with_scheme(RsaScheme::Null)
                        .with_key_bits(key_bits)
                        .with_exponent(RsaExponent::default())
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.decrypt())
                        .build()?,
                )
                .with_rsa_unique_identifier(unique)
        }
        AsymmetricAlgorithmSelection::Ecc(ecc_curve) => {
            let (hash_alg, auth_policy, symmetric, xy_size) = match ecc_curve {
                EccCurve::NistP256 => (
                    HashingAlgorithm::Sha256,
                    Digest::try_from(AUTH_POLICY_A_SHA256.as_slice())?,
                    SymmetricDefinitionObject::AES_128_CFB,
                    32,
                ),
                EccCurve::NistP384 => (
                    HashingAlgorithm::Sha384,
                    Digest::try_from(AUTH_POLICY_B_SHA384.as_slice())?,
                    SymmetricDefinitionObject::AES_256_CFB,
                    0,
                ),
                EccCurve::NistP521 => (
                    HashingAlgorithm::Sha512,
                    Digest::try_from(AUTH_POLICY_B_SHA512.as_slice())?,
                    SymmetricDefinitionObject::AES_256_CFB,
                    0,
                ),
                EccCurve::Sm2P256 => (
                    HashingAlgorithm::Sm3_256,
                    Digest::try_from(AUTH_POLICY_B_SM3_256.as_slice())?,
                    SymmetricDefinitionObject::SM4_128_CFB,
                    0,
                ),
                // Other curves are not supported in the spec, so return a error
                _ => return Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            };
            PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_name_hashing_algorithm(hash_alg)
                .with_object_attributes(obj_attrs)
                .with_auth_policy(auth_policy)
                .with_ecc_parameters(
                    PublicEccParametersBuilder::new()
                        .with_symmetric(symmetric)
                        .with_ecc_scheme(EccScheme::Null)
                        .with_curve(ecc_curve)
                        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                        .with_is_signing_key(obj_attrs.sign_encrypt())
                        .with_is_decryption_key(obj_attrs.decrypt())
                        .with_restricted(obj_attrs.decrypt())
                        .build()?,
                )
                .with_ecc_unique_identifier(EccPoint::new(
                    EccParameter::try_from(vec![0u8; xy_size])?,
                    EccParameter::try_from(vec![0u8; xy_size])?,
                ))
        }
    };

    let key_builder = if let Some(ref k) = key_customization {
        k.template(key_builder)
    } else {
        key_builder
    };
    key_builder.build()
}

/// Create the Endorsement Key object from the specification templates
///
/// <div class="warning">
///
/// The API of this function will be changed to that of [`create_ek_object_2`]
/// in the next major version.
///
/// </div>
pub fn create_ek_object<IKC: IntoKeyCustomization>(
    context: &mut Context,
    alg: AsymmetricAlgorithm,
    key_customization: IKC,
) -> Result<KeyHandle> {
    create_ek_object_2(
        context,
        AsymmetricAlgorithmSelection::try_from(alg)?,
        key_customization,
    )
}

/// Create the Endorsement Key object from the specification templates
///
/// <div class="warning">
///
/// This function will be removed in the next major version.
///
/// </div>
pub fn create_ek_object_2<IKC: IntoKeyCustomization>(
    context: &mut Context,
    alg: AsymmetricAlgorithmSelection,
    key_customization: IKC,
) -> Result<KeyHandle> {
    let ek_public = create_ek_public_from_default_template_2(alg, key_customization)?;

    Ok(context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, ek_public, None, None, None, None)
        })?
        .key_handle)
}

/// Retrieve the Endorsement Key public certificate from the TPM
pub fn retrieve_ek_pubcert(
    context: &mut Context,
    alg: AsymmetricAlgorithmSelection,
) -> Result<Vec<u8>> {
    let nv_idx = match alg {
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048) => RSA_2048_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa3072) => RSA_3072_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa4096) => RSA_4096_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256) => ECC_P256_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384) => ECC_P384_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP521) => ECC_P521_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::Sm2P256) => {
            ECC_P256_SM2_EK_CERTIFICATE_NV_INDEX
        }
        _ => return Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
    };

    let nv_idx = NvIndexTpmHandle::new(nv_idx).unwrap();

    let nv_auth_handle = TpmHandle::NvIndex(nv_idx);
    let nv_auth_handle = context.execute_without_session(|ctx| {
        ctx.tr_from_tpm_public(nv_auth_handle)
            .map(|v| NvAuth::NvIndex(v.into()))
    })?;

    context.execute_with_nullauth_session(|ctx| nv::read_full(ctx, nv_auth_handle, nv_idx))
}
