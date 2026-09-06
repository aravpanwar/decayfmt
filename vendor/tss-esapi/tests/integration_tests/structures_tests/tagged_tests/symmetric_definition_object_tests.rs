// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    interface_types::{
        algorithm::{SymmetricMode, SymmetricObject},
        key_bits::{AesKeyBits, CamelliaKeyBits, Sm4KeyBits},
    },
    structures::SymmetricDefinitionObject,
    tss2_esys::{TPMT_SYM_DEF_OBJECT, TPMU_SYM_KEY_BITS, TPMU_SYM_MODE},
};

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
            let expected_tpmt_sym_def_object = TPMT_SYM_DEF_OBJECT {
                algorithm: SymmetricObject::Aes.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    aes: expected_key_bits.into(),
                },
                mode: TPMU_SYM_MODE {
                    aes: expected_mode.into(),
                },
            };

            let sym_def_object = SymmetricDefinitionObject::try_from(expected_tpmt_sym_def_object)
                .expect("Failed to convert TPMT_SYM_DEF_OBJECT into SymmetricDefinitionObject");

            if let SymmetricDefinitionObject::Aes { key_bits, mode } = sym_def_object {
                assert_eq!(
                    expected_key_bits, key_bits, "TPMT_SYM_DEF_OBJECT converted into SymmetricDefinitionObject did not contain the correct value for 'key_bits'"
                );
                assert_eq!(expected_mode, mode,  "TPMT_SYM_DEF_OBJECT converted into SymmetricDefinitionObject did not contain the correct value for 'mode'");
            } else {
                panic!("SymmetricDefinitionObject converted from TPMT_SYM_DEF_OBJECT did not contain the expected algorithm AES");
            }

            let actual_tpmt_sym_def_object = TPMT_SYM_DEF_OBJECT::from(sym_def_object);

            crate::common::ensure_tpmt_sym_def_object_equality(
                &expected_tpmt_sym_def_object,
                &actual_tpmt_sym_def_object,
            );
        }
    }
}

#[test]
fn test_valid_sm4_conversions() {
    for expected_mode in SYM_MODES {
        let expected_key_bits = Sm4KeyBits::Sm4_128;
        let expected_tpmt_sym_def_object = TPMT_SYM_DEF_OBJECT {
            algorithm: SymmetricObject::Sm4.into(),
            keyBits: TPMU_SYM_KEY_BITS {
                sm4: expected_key_bits.into(),
            },
            mode: TPMU_SYM_MODE {
                sm4: expected_mode.into(),
            },
        };

        let sym_def_object = SymmetricDefinitionObject::try_from(expected_tpmt_sym_def_object)
            .expect("Failed to convert TPMT_SYM_DEF_OBJECT into SymmetricDefinitionObject");

        if let SymmetricDefinitionObject::Sm4 { key_bits, mode } = sym_def_object {
            assert_eq!(
                    expected_key_bits, key_bits, "TPMT_SYM_DEF_OBJECT converted into SymmetricDefinitionObject did not contain the correct value for 'key_bits'"
                );
            assert_eq!(expected_mode, mode,  "TPMT_SYM_DEF_OBJECT converted into SymmetricDefinitionObject did not contain the correct value for 'mode'");
        } else {
            panic!("SymmetricDefinitionObject converted from TPMT_SYM_DEF_OBJECT did not contain the expected algorithm SM4");
        }

        let actual_tpmt_sym_def_object = TPMT_SYM_DEF_OBJECT::from(sym_def_object);

        crate::common::ensure_tpmt_sym_def_object_equality(
            &expected_tpmt_sym_def_object,
            &actual_tpmt_sym_def_object,
        );
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
            let expected_tpmt_sym_def_object = TPMT_SYM_DEF_OBJECT {
                algorithm: SymmetricObject::Camellia.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    camellia: expected_key_bits.into(),
                },
                mode: TPMU_SYM_MODE {
                    camellia: expected_mode.into(),
                },
            };

            let sym_def_object = SymmetricDefinitionObject::try_from(expected_tpmt_sym_def_object)
                .expect("Failed to convert TPMT_SYM_DEF_OBJECT into SymmetricDefinitionObject");

            if let SymmetricDefinitionObject::Camellia { key_bits, mode } = sym_def_object {
                assert_eq!(
                    expected_key_bits, key_bits, "TPMT_SYM_DEF_OBJECT converted into SymmetricDefinitionObject did not contain the correct value for 'key_bits'"
                );
                assert_eq!(expected_mode, mode,  "TPMT_SYM_DEF_OBJECT converted into SymmetricDefinitionObject did not contain the correct value for 'mode'");
            } else {
                panic!("SymmetricDefinitionObject converted from TPMT_SYM_DEF_OBJECT did not contain the expected algorithm CAMELLIA");
            }

            let actual_tpmt_sym_def_object = TPMT_SYM_DEF_OBJECT::from(sym_def_object);

            crate::common::ensure_tpmt_sym_def_object_equality(
                &expected_tpmt_sym_def_object,
                &actual_tpmt_sym_def_object,
            );
        }
    }
}

#[test]
fn test_valid_null_conversions() {
    let expected_tpmt_sym_def_object = TPMT_SYM_DEF_OBJECT {
        algorithm: SymmetricObject::Null.into(),
        keyBits: Default::default(),
        mode: Default::default(),
    };

    let sym_def_object = SymmetricDefinitionObject::try_from(expected_tpmt_sym_def_object)
        .expect("Failed to convert TPMT_SYM_DEF_OBJECT into SymmetricDefinitionObject");

    if sym_def_object != SymmetricDefinitionObject::Null {
        panic!("SymmetricDefinitionObject converted from TPMT_SYM_DEF_OBJECT did not contain the expected algorithm NULL");
    }

    let actual_tpmt_sym_def_object = TPMT_SYM_DEF_OBJECT::from(sym_def_object);

    crate::common::ensure_tpmt_sym_def_object_equality(
        &expected_tpmt_sym_def_object,
        &actual_tpmt_sym_def_object,
    );
}
