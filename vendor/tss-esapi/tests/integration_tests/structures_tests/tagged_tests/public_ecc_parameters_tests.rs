// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::interface_types::algorithm::*;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::*;
use tss_esapi::Error;
use tss_esapi::WrapperErrorKind;

#[test]
fn test_restricted_decryption_with_default_symmetric() {
    assert!(matches!(
        PublicEccParametersBuilder::new()
            .with_restricted(true)
            .with_is_decryption_key(true)
            .with_ecc_scheme(EccScheme::Null)
            .with_curve(EccCurve::NistP256)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build(),
        Err(Error::WrapperError(WrapperErrorKind::ParamsMissing))
    ));
}

#[test]
fn test_restricted_decryption_with_null_symmetric() {
    assert!(matches!(
        PublicEccParametersBuilder::new()
            .with_restricted(true)
            .with_is_decryption_key(true)
            .with_ecc_scheme(EccScheme::Null)
            .with_curve(EccCurve::NistP256)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::Null)
            .build(),
        Err(Error::WrapperError(WrapperErrorKind::InconsistentParams))
    ));
}

#[test]
fn test_restricted_decryption_with_wrong_symmetric() {
    assert!(PublicEccParametersBuilder::new()
        .with_restricted(true)
        .with_is_decryption_key(true)
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .build()
        .is_ok());
}

#[test]
fn test_signing_with_default_symmetric() {
    assert!(PublicEccParametersBuilder::new()
        .with_restricted(false)
        .with_is_decryption_key(false)
        .with_is_signing_key(true)
        .with_ecc_scheme(
            EccScheme::create(
                EccSchemeAlgorithm::EcDsa,
                Some(HashingAlgorithm::Sha256),
                None
            )
            .unwrap()
        )
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::Null)
        .build()
        .is_ok());
}

#[test]
fn test_signing_with_wrong_symmetric() {
    assert!(matches!(
        PublicEccParametersBuilder::new()
            .with_restricted(false)
            .with_is_decryption_key(false)
            .with_is_signing_key(true)
            .with_ecc_scheme(
                EccScheme::create(
                    EccSchemeAlgorithm::EcDsa,
                    Some(HashingAlgorithm::Sha256),
                    None
                )
                .unwrap()
            )
            .with_curve(EccCurve::NistP256)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
            .build(),
        Err(Error::WrapperError(WrapperErrorKind::InconsistentParams))
    ));
}

#[test]
fn test_signing_with_mismatched_scheme_nist() {
    assert_eq!(
        PublicEccParametersBuilder::new()
            .with_restricted(false)
            .with_is_decryption_key(false)
            .with_is_signing_key(true)
            .with_curve(EccCurve::NistP256)
            .with_ecc_scheme(
                EccScheme::create(
                    EccSchemeAlgorithm::Sm2,
                    Some(HashingAlgorithm::Sha256),
                    None
                )
                .unwrap()
            )
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::Null)
            .build(),
        Err(Error::WrapperError(WrapperErrorKind::InconsistentParams))
    );
}

#[test]
fn test_signing_with_mismatched_scheme_sm2() {
    assert_eq!(
        PublicEccParametersBuilder::new()
            .with_restricted(false)
            .with_is_decryption_key(false)
            .with_is_signing_key(true)
            .with_curve(EccCurve::Sm2P256)
            .with_ecc_scheme(
                EccScheme::create(
                    EccSchemeAlgorithm::EcDsa,
                    Some(HashingAlgorithm::Sha256),
                    None
                )
                .unwrap()
            )
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::Null)
            .build(),
        Err(Error::WrapperError(WrapperErrorKind::InconsistentParams))
    );
}

#[test]
fn test_signing_with_mismatched_scheme_bn() {
    assert_eq!(
        PublicEccParametersBuilder::new()
            .with_restricted(false)
            .with_is_decryption_key(false)
            .with_is_signing_key(true)
            .with_curve(EccCurve::BnP256)
            .with_ecc_scheme(
                EccScheme::create(
                    EccSchemeAlgorithm::EcDsa,
                    Some(HashingAlgorithm::Sha256),
                    None
                )
                .unwrap()
            )
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::Null)
            .build(),
        Err(Error::WrapperError(WrapperErrorKind::InconsistentParams))
    );
}
