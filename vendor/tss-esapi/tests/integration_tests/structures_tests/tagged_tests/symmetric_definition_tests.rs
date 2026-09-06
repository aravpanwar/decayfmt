// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    constants::AlgorithmIdentifier,
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricAlgorithm, SymmetricMode},
        key_bits::{AesKeyBits, CamelliaKeyBits, Sm4KeyBits},
    },
    structures::SymmetricDefinition,
    tss2_esys::{TPMT_SYM_DEF, TPMU_SYM_KEY_BITS, TPMU_SYM_MODE},
    Error, WrapperErrorKind,
};

use std::convert::TryFrom;

const SYM_MODES: [SymmetricMode; 5] = [
    SymmetricMode::Cfb,
    SymmetricMode::Cbc,
    SymmetricMode::Ctr,
    SymmetricMode::Ecb,
    SymmetricMode::Ofb,
];

#[test]
fn test_valid_aes_conversions() {
    const AES_KEY_BITS: [AesKeyBits; 3] =
        [AesKeyBits::Aes128, AesKeyBits::Aes192, AesKeyBits::Aes256];
    for expected_mode in SYM_MODES {
        for expected_key_bits in AES_KEY_BITS {
            let expected_tpmt_sym_def = TPMT_SYM_DEF {
                algorithm: SymmetricAlgorithm::Aes.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    aes: expected_key_bits.into(),
                },
                mode: TPMU_SYM_MODE {
                    aes: expected_mode.into(),
                },
            };

            let sym_def = SymmetricDefinition::try_from(expected_tpmt_sym_def)
                .expect("Failed to convert TPMT_SYM_DEF into SymmetricDefinition");

            if let SymmetricDefinition::Aes { key_bits, mode } = sym_def {
                assert_eq!(
                    expected_key_bits, key_bits, "TPMT_SYM_DEF converted into SymmetricDefinition did not contain the correct value for 'key_bits'"
                );
                assert_eq!(expected_mode, mode,  "TPMT_SYM_DEF converted into SymmetricDefinition did not contain the correct value for 'mode'");
            } else {
                panic!("SymmetricDefinition converted from TPMT_SYM_DEF did not contain the expected algorithm AES");
            }

            let actual_tpmt_sym_def = TPMT_SYM_DEF::try_from(sym_def)
                .expect("Failed to Convert SymmetricDefinition into TPMT_SYM_DEF");

            crate::common::ensure_tpmt_sym_def_equality(
                &expected_tpmt_sym_def,
                &actual_tpmt_sym_def,
            );
        }
    }
}

#[test]
fn test_valid_sm4_conversions() {
    for expected_mode in SYM_MODES {
        let expected_key_bits = Sm4KeyBits::Sm4_128;
        let expected_tpmt_sym_def = TPMT_SYM_DEF {
            algorithm: SymmetricAlgorithm::Sm4.into(),
            keyBits: TPMU_SYM_KEY_BITS {
                sm4: expected_key_bits.into(),
            },
            mode: TPMU_SYM_MODE {
                sm4: expected_mode.into(),
            },
        };

        let sym_def = SymmetricDefinition::try_from(expected_tpmt_sym_def)
            .expect("Failed to convert TPMT_SYM_DEF into SymmetricDefinition");

        if let SymmetricDefinition::Sm4 { key_bits, mode } = sym_def {
            assert_eq!(
                    expected_key_bits, key_bits, "TPMT_SYM_DEF converted into SymmetricDefinition did not contain the correct value for 'key_bits'"
                );
            assert_eq!(expected_mode, mode,  "TPMT_SYM_DEF converted into SymmetricDefinition did not contain the correct value for 'mode'");
        } else {
            panic!("SymmetricDefinition converted from TPMT_SYM_DEF did not contain the expected algorithm SM4");
        }

        let actual_tpmt_sym_def = TPMT_SYM_DEF::try_from(sym_def)
            .expect("Failed to Convert SymmetricDefinition into TPMT_SYM_DEF");

        crate::common::ensure_tpmt_sym_def_equality(&expected_tpmt_sym_def, &actual_tpmt_sym_def);
    }
}

#[test]
fn test_valid_camellia_conversions() {
    const CAMELLIA_KEY_BITS: [CamelliaKeyBits; 3] = [
        CamelliaKeyBits::Camellia128,
        CamelliaKeyBits::Camellia192,
        CamelliaKeyBits::Camellia256,
    ];
    for expected_mode in SYM_MODES {
        for expected_key_bits in CAMELLIA_KEY_BITS {
            let expected_tpmt_sym_def = TPMT_SYM_DEF {
                algorithm: SymmetricAlgorithm::Camellia.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    camellia: expected_key_bits.into(),
                },
                mode: TPMU_SYM_MODE {
                    camellia: expected_mode.into(),
                },
            };

            let sym_def = SymmetricDefinition::try_from(expected_tpmt_sym_def)
                .expect("Failed to convert TPMT_SYM_DEF into SymmetricDefinition");

            if let SymmetricDefinition::Camellia { key_bits, mode } = sym_def {
                assert_eq!(
                    expected_key_bits, key_bits, "TPMT_SYM_DEF converted into SymmetricDefinition did not contain the correct value for 'key_bits'"
                );
                assert_eq!(expected_mode, mode,  "TPMT_SYM_DEF converted into SymmetricDefinition did not contain the correct value for 'mode'");
            } else {
                panic!("SymmetricDefinition converted from TPMT_SYM_DEF did not contain the expected algorithm CAMELLIA");
            }

            let actual_tpmt_sym_def = TPMT_SYM_DEF::try_from(sym_def)
                .expect("Failed to Convert SymmetricDefinition into TPMT_SYM_DEF");

            crate::common::ensure_tpmt_sym_def_equality(
                &expected_tpmt_sym_def,
                &actual_tpmt_sym_def,
            );
        }
    }
}

#[test]
fn test_valid_xor_conversions() {
    const HASHING_ALGORITHMS: [HashingAlgorithm; 8] = [
        HashingAlgorithm::Sha1,
        HashingAlgorithm::Sha256,
        HashingAlgorithm::Sha384,
        HashingAlgorithm::Sha512,
        HashingAlgorithm::Sm3_256,
        HashingAlgorithm::Sha3_256,
        HashingAlgorithm::Sha3_384,
        HashingAlgorithm::Sha3_512,
    ];
    for expected_hashing_algorithm in HASHING_ALGORITHMS {
        let expected_tpmt_sym_def = TPMT_SYM_DEF {
            algorithm: SymmetricAlgorithm::Xor.into(),
            keyBits: TPMU_SYM_KEY_BITS {
                exclusiveOr: expected_hashing_algorithm.into(),
            },
            mode: Default::default(),
        };

        let sym_def = SymmetricDefinition::try_from(expected_tpmt_sym_def)
            .expect("Failed to convert TPMT_SYM_DEF into SymmetricDefinition");

        if let SymmetricDefinition::Xor { hashing_algorithm } = sym_def {
            assert_eq!(
                expected_hashing_algorithm,
                hashing_algorithm,
                "TPMT_SYM_DEF converted into SymmetricDefinition did not contain the correct value for 'key_bits'",
                );
        } else {
            panic!("SymmetricDefinition converted from TPMT_SYM_DEF did not contain the expected algorithm XOR");
        }

        let actual_tpmt_sym_def = TPMT_SYM_DEF::try_from(sym_def)
            .expect("Failed to Convert SymmetricDefinition into TPMT_SYM_DEF");

        crate::common::ensure_tpmt_sym_def_equality(&expected_tpmt_sym_def, &actual_tpmt_sym_def);
    }
}

#[test]
fn test_valid_null_conversions() {
    let expected_tpmt_sym_def = TPMT_SYM_DEF {
        algorithm: SymmetricAlgorithm::Null.into(),
        keyBits: Default::default(),
        mode: Default::default(),
    };

    let sym_def = SymmetricDefinition::try_from(expected_tpmt_sym_def)
        .expect("Failed to convert TPMT_SYM_DEF into SymmetricDefinition");

    if sym_def != SymmetricDefinition::Null {
        panic!("SymmetricDefinition converted from TPMT_SYM_DEF did not contain the expected algorithm NULL");
    }

    let actual_tpmt_sym_def = TPMT_SYM_DEF::try_from(sym_def)
        .expect("Failed to Convert SymmetricDefinition into TPMT_SYM_DEF");

    crate::common::ensure_tpmt_sym_def_equality(&expected_tpmt_sym_def, &actual_tpmt_sym_def);
}

#[test]
fn test_invalid_symmetric_algorithm_conversion() {
    let invalid_alg_tpmt_sym_def = TPMT_SYM_DEF {
        algorithm: AlgorithmIdentifier::RsaPss.into(),
        keyBits: Default::default(),
        mode: Default::default(),
    };

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        SymmetricDefinition::try_from(invalid_alg_tpmt_sym_def),
        "Converting TPMT_SYM_DEF with an invalid symmetric algorithm did not produce the expected error"
    );
}

#[test]
fn test_invalid_xor_with_null_conversions() {
    let invalid_alg_tpmt_sym_def = TPMT_SYM_DEF {
        algorithm: SymmetricAlgorithm::Xor.into(),
        keyBits: TPMU_SYM_KEY_BITS {
            exclusiveOr: HashingAlgorithm::Null.into(),
        },
        mode: Default::default(),
    };

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        SymmetricDefinition::try_from(invalid_alg_tpmt_sym_def),
        "Converting TPMT_SYM_DEF with an invalid XOR hashing algorithm did not produce the expected error"
    );

    let invalid_sym_def = SymmetricDefinition::Xor {
        hashing_algorithm: HashingAlgorithm::Null,
    };

    if let Err(actual_error) = TPMT_SYM_DEF::try_from(invalid_sym_def) {
        assert_eq!(
            Error::WrapperError(WrapperErrorKind::InvalidParam),
            actual_error,
            "Converting SymmetricDefinition with invalid XOR hashing algorithm did not produce the expected error"
        );
    } else {
        panic!("Converting SymmetricDefinition with invalid XOR hashing algorithm did not produce an error");
    }
}
