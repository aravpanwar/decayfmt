// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::AlgorithmIdentifier,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
    },
    structures::{
        EccScheme, HmacScheme, KeyDerivationFunctionScheme, KeyedHashScheme, PublicEccParameters,
        PublicKeyedHashParameters, PublicParameters, PublicRsaParameters, RsaScheme,
        SymmetricCipherParameters, SymmetricDefinitionObject,
    },
    tss2_esys::{TPMT_PUBLIC_PARMS, TPMU_PUBLIC_PARMS},
    Error, WrapperErrorKind,
};

#[test]
fn test_valid_rsa_parameters_conversions() {
    let expected_public_rsa_parameters = PublicRsaParameters::builder()
        .with_restricted(true)
        .with_is_decryption_key(true)
        .with_scheme(RsaScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_key_bits(RsaKeyBits::Rsa1024)
        .build()
        .expect("Failed to build public rsa parameters");

    let expected_tpmt_public_parms = TPMT_PUBLIC_PARMS {
        type_: PublicAlgorithm::Rsa.into(),
        parameters: TPMU_PUBLIC_PARMS {
            rsaDetail: expected_public_rsa_parameters.into(),
        },
    };

    let actual_public_parameters = PublicParameters::try_from(expected_tpmt_public_parms)
        .expect("Failed to convert TPMT_PUBLIC_PARMS into PublicParameters");

    if let PublicParameters::Rsa(actual_public_rsa_parameters) = actual_public_parameters {
        assert_eq!(
        expected_public_rsa_parameters,
        actual_public_rsa_parameters,
        "PublicRsaParameters converted from TPMT_PUBLIC_PARMS did not contain the expected values"
    );
    } else {
        panic!("TPMT_PUBLIC_PARMS did not convert into the expected value");
    }

    crate::common::ensure_tpmt_public_parms_equality(
        &expected_tpmt_public_parms,
        &actual_public_parameters.into(),
    );
}

#[test]
fn test_valid_ecc_parameters_conversion() {
    let expected_public_ecc_parameters = PublicEccParameters::builder()
        .with_restricted(true)
        .with_is_decryption_key(true)
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .build()
        .expect("Failed to build public ECC parameters");

    let expected_tpmt_public_parms = TPMT_PUBLIC_PARMS {
        type_: PublicAlgorithm::Ecc.into(),
        parameters: TPMU_PUBLIC_PARMS {
            eccDetail: expected_public_ecc_parameters.into(),
        },
    };

    let actual_public_parameters = PublicParameters::try_from(expected_tpmt_public_parms)
        .expect("Failed to convert TPMT_PUBLIC_PARMS into PublicParameters");

    if let PublicParameters::Ecc(actual_public_ecc_parameters) = actual_public_parameters {
        assert_eq!(
            expected_public_ecc_parameters,
            actual_public_ecc_parameters,
            "PublicEccParameters converted from TPMT_PUBLIC_PARMS did not contain the expected values"
        );
    } else {
        panic!("TPMT_PUBLIC_PARMS did not convert into the expected value");
    }

    crate::common::ensure_tpmt_public_parms_equality(
        &expected_tpmt_public_parms,
        &actual_public_parameters.into(),
    );
}

#[test]
fn test_valid_keyed_hash_parameters_conversion() {
    let expected_public_keyed_hash_parameters =
        PublicKeyedHashParameters::new(KeyedHashScheme::Hmac {
            hmac_scheme: HmacScheme::new(HashingAlgorithm::Sha256),
        });

    let expected_tpmt_public_parms = TPMT_PUBLIC_PARMS {
        type_: PublicAlgorithm::KeyedHash.into(),
        parameters: TPMU_PUBLIC_PARMS {
            keyedHashDetail: expected_public_keyed_hash_parameters.into(),
        },
    };

    let actual_public_parameters = PublicParameters::try_from(expected_tpmt_public_parms)
        .expect("Failed to convert TPMT_PUBLIC_PARMS into PublicParameters");

    if let PublicParameters::KeyedHash(actual_public_keyed_hash_parameters) =
        actual_public_parameters
    {
        assert_eq!(
                expected_public_keyed_hash_parameters,
                actual_public_keyed_hash_parameters,
                "PublicKeyedHashParameters converted from TPMT_PUBLIC_PARMS did not contain the expected values"
            );
    } else {
        panic!("TPMT_PUBLIC_PARMS did not convert into the expected value");
    }

    crate::common::ensure_tpmt_public_parms_equality(
        &expected_tpmt_public_parms,
        &actual_public_parameters.into(),
    );
}

#[test]
fn test_valid_symmetric_cipher_parameters_conversion() {
    let expected_symmetric_cipher_parameters =
        SymmetricCipherParameters::new(SymmetricDefinitionObject::AES_128_CFB);

    let expected_tpmt_public_parms = TPMT_PUBLIC_PARMS {
        type_: PublicAlgorithm::SymCipher.into(),
        parameters: TPMU_PUBLIC_PARMS {
            symDetail: expected_symmetric_cipher_parameters.into(),
        },
    };

    let actual_public_parameters = PublicParameters::try_from(expected_tpmt_public_parms)
        .expect("Failed to convert TPMT_PUBLIC_PARMS into PublicParameters");

    if let PublicParameters::SymCipher(actual_public_symmetric_cipher_parameters) =
        actual_public_parameters
    {
        assert_eq!(
            expected_symmetric_cipher_parameters,
                actual_public_symmetric_cipher_parameters,
                "SymmetricCipherParameters converted from TPMT_PUBLIC_PARMS did not contain the expected values"
            );
    } else {
        panic!("TPMT_PUBLIC_PARMS did not convert into the expected value");
    }

    crate::common::ensure_tpmt_public_parms_equality(
        &expected_tpmt_public_parms,
        &actual_public_parameters.into(),
    );
}

#[test]
fn test_conversion_failure_due_to_invalid_public_algorithm() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        PublicParameters::try_from(TPMT_PUBLIC_PARMS {
            type_: AlgorithmIdentifier::Sha256.into(),
            parameters: Default::default(),
        })
    );
}
