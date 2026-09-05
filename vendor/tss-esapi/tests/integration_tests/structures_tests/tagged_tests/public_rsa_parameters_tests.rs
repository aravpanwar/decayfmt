// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::*;
use tss_esapi::Error;
use tss_esapi::WrapperErrorKind;

#[test]
fn test_restricted_decryption_with_default_symmetric() {
    assert!(matches!(
        PublicRsaParametersBuilder::new()
            .with_restricted(true)
            .with_is_decryption_key(true)
            .with_scheme(RsaScheme::Null)
            .with_key_bits(RsaKeyBits::Rsa1024)
            .build(),
        Err(Error::WrapperError(WrapperErrorKind::ParamsMissing))
    ));
}

#[test]
fn test_restricted_decryption_with_null_symmetric() {
    assert!(matches!(
        PublicRsaParametersBuilder::new()
            .with_restricted(true)
            .with_is_decryption_key(true)
            .with_scheme(RsaScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::Null)
            .with_key_bits(RsaKeyBits::Rsa1024)
            .build(),
        Err(Error::WrapperError(WrapperErrorKind::InconsistentParams))
    ));
}

#[test]
fn test_restricted_decryption_with_wrong_symmetric() {
    assert!(PublicRsaParametersBuilder::new()
        .with_restricted(true)
        .with_is_decryption_key(true)
        .with_scheme(RsaScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_key_bits(RsaKeyBits::Rsa1024)
        .build()
        .is_ok());
}

#[test]
fn test_signing_with_default_symmetric() {
    assert!(PublicRsaParametersBuilder::new()
        .with_restricted(false)
        .with_is_decryption_key(false)
        .with_is_signing_key(true)
        .with_scheme(RsaScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_key_bits(RsaKeyBits::Rsa1024)
        .build()
        .is_ok());
}

#[test]
fn test_signing_with_wrong_symmetric() {
    assert!(matches!(
        PublicRsaParametersBuilder::new()
            .with_restricted(false)
            .with_is_decryption_key(false)
            .with_is_signing_key(true)
            .with_scheme(RsaScheme::Null)
            .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
            .with_key_bits(RsaKeyBits::Rsa1024)
            .build(),
        Err(Error::WrapperError(WrapperErrorKind::InconsistentParams))
    ));
}
