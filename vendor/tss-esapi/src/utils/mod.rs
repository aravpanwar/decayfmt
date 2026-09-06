// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Utility module
//!
//! This module mostly contains helper elements meant to act as either wrappers around FFI-level
//! structs or builders for them, along with other convenience elements.
//! The naming structure usually takes the names inherited from the TSS spec and applies Rust
//! guidelines to them. Structures that are meant to act as builders have `Builder` appended to
//! type name. Unions are converted to Rust `enum`s by dropping the `TPMU` qualifier and appending
//! `Union`.
use crate::attributes::ObjectAttributesBuilder;
use crate::constants::PropertyTag;
use crate::interface_types::{
    algorithm::{HashingAlgorithm, PublicAlgorithm},
    ecc::EccCurve,
    key_bits::RsaKeyBits,
};
use crate::structures::{
    EccPoint, EccScheme, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa,
    PublicRsaParametersBuilder, RsaExponent, RsaScheme, SymmetricDefinitionObject,
};
use crate::tss2_esys::*;
use crate::{Context, Error, Result, WrapperErrorKind};
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};

/// Rust native wrapper for `TPMS_CONTEXT` objects.
///
/// This structure is intended to help with persisting object contexts. As the main reason for
/// saving the context of an object is to be able to reuse it later, on demand, a serializable
/// structure is most commonly needed. `TpmsContext` implements the `Serialize` and `Deserialize`
/// defined by `serde`.
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize)]
#[zeroize(drop)]
pub struct TpmsContext {
    sequence: u64,
    saved_handle: TPMI_DH_CONTEXT,
    hierarchy: TPMI_RH_HIERARCHY,
    context_blob: Vec<u8>,
}

impl TpmsContext {
    /// Get a reference to the `context_blob` field
    pub fn context_blob(&self) -> &Vec<u8> {
        &self.context_blob
    }
}

// TODO: Replace with `From`
impl TryFrom<TPMS_CONTEXT> for TpmsContext {
    type Error = Error;

    fn try_from(tss2_context: TPMS_CONTEXT) -> Result<Self> {
        let mut context = TpmsContext {
            sequence: tss2_context.sequence,
            saved_handle: tss2_context.savedHandle,
            hierarchy: tss2_context.hierarchy,
            context_blob: tss2_context.contextBlob.buffer.to_vec(),
        };
        context
            .context_blob
            .truncate(tss2_context.contextBlob.size.into());
        Ok(context)
    }
}

#[allow(clippy::needless_update)]
impl TryFrom<TpmsContext> for TPMS_CONTEXT {
    type Error = Error;

    fn try_from(context: TpmsContext) -> Result<Self> {
        let buffer_size = context.context_blob.len();
        if buffer_size > 5188 {
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut buffer = [0_u8; 5188];
        for (i, val) in context.context_blob.iter().enumerate() {
            buffer[i] = *val;
        }
        Ok(TPMS_CONTEXT {
            sequence: context.sequence,
            savedHandle: context.saved_handle,
            hierarchy: context.hierarchy,
            contextBlob: TPM2B_CONTEXT_DATA {
                size: buffer_size.try_into().unwrap(), // should not panic given the check above
                buffer,
            },
            ..Default::default()
        })
    }
}

/// Create the [Public] structure for a restricted decryption key.
///
/// * `symmetric` - Cipher to be used for decrypting children of the key
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key
pub fn create_restricted_decryption_rsa_public(
    symmetric: SymmetricDefinitionObject,
    rsa_key_bits: RsaKeyBits,
    rsa_pub_exponent: RsaExponent,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_restricted_decryption_key(
                symmetric,
                rsa_key_bits,
                rsa_pub_exponent,
            )
            .build()?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
}

/// Create the [Public] structure for an unrestricted encryption/decryption key.
///
/// * `symmetric` - Cipher to be used for decrypting children of the key
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key
pub fn create_unrestricted_encryption_decryption_rsa_public(
    rsa_key_bits: RsaKeyBits,
    rsa_pub_exponent: RsaExponent,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(rsa_key_bits)
                .with_exponent(rsa_pub_exponent)
                .with_is_signing_key(true)
                .with_is_decryption_key(true)
                .with_restricted(false)
                .build()?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
}

/// Create the [Public] structure for an RSA unrestricted signing key.
///
/// * `scheme` - RSA scheme to be used for signing
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key
pub fn create_unrestricted_signing_rsa_public(
    scheme: RsaScheme,
    rsa_key_bits: RsaKeyBits,
    rsa_pub_exponent: RsaExponent,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_unrestricted_signing_key(
                scheme,
                rsa_key_bits,
                rsa_pub_exponent,
            )
            .build()?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
}

/// Create the [Public] structure for an RSA unrestricted signing key.
///
/// * `scheme` - RSA scheme to be used for signing
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key
/// * `rsa_public_key` - The public part of the RSA key that is going to be used as unique identifier.
pub fn create_unrestricted_signing_rsa_public_with_unique(
    scheme: RsaScheme,
    rsa_key_bits: RsaKeyBits,
    rsa_pub_exponent: RsaExponent,
    rsa_public_key: PublicKeyRsa,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_unrestricted_signing_key(
                scheme,
                rsa_key_bits,
                rsa_pub_exponent,
            )
            .build()?,
        )
        .with_rsa_unique_identifier(rsa_public_key)
        .build()
}

/// Create the [Public] structure for an ECC unrestricted signing key.
///
/// * `scheme` - Asymmetric scheme to be used for signing; *must* be an RSA signing scheme
/// * `curve` - identifier of the precise curve to be used with the key
pub fn create_unrestricted_signing_ecc_public(
    scheme: EccScheme,
    curve: EccCurve,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(scheme, curve).build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

/// Container for public key values
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, PartialEq, Eq)]
pub enum PublicKey {
    /// RSA public modulus (see 27.5.3.4 in the Architecture spec)
    ///
    /// This is the value extracted from the `unique` part of `TPMT_PUBLIC`.
    /// The exponent is not included here as the expectation is that the
    /// exponent is always pinned to 65537 (2^16 + 1).
    ///
    /// The modulus is in Big-Endian format.
    Rsa(Vec<u8>),
    /// Public elliptic curve point (see 27.5.3.5 in the Architecture spec)
    ///
    /// The x and y coordinates are given uncompressed.
    Ecc { x: Vec<u8>, y: Vec<u8> },
}

impl TryFrom<Public> for PublicKey {
    type Error = Error;

    fn try_from(public: Public) -> Result<Self> {
        match public {
            Public::Rsa { unique, .. } => Ok(PublicKey::Rsa(unique.value().to_vec())),
            Public::Ecc { unique, .. } => Ok(PublicKey::Ecc {
                x: unique.x().value().to_vec(),
                y: unique.y().value().to_vec(),
            }),
            _ => Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm)),
        }
    }
}

fn tpm_int_to_string(num: u32) -> String {
    num.to_be_bytes()
        .iter()
        .filter(|x| **x != 0)
        .map(|x| char::from(*x))
        .collect()
}

/// Get the TPM vendor name
pub fn get_tpm_vendor(context: &mut Context) -> Result<String> {
    // Retrieve the TPM property values
    Ok([
        PropertyTag::VendorString1,
        PropertyTag::VendorString2,
        PropertyTag::VendorString3,
        PropertyTag::VendorString4,
    ]
    .iter()
    // Retrieve property values
    .map(|prop_id| context.get_tpm_property(*prop_id))
    // Collect and return an error if we got one
    .collect::<Result<Vec<Option<u32>>>>()?
    .iter()
    // Filter out the Option::None values
    .filter_map(|x| *x)
    // Filter out zero values
    .filter(|x| *x != 0)
    // Map through int_to_string
    .map(tpm_int_to_string)
    // Collect to a single string
    .collect())
}
