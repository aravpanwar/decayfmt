// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    constants::tss::{
        TPM2_ALG_AES, TPM2_ALG_CAMELLIA, TPM2_ALG_ECC, TPM2_ALG_ECDAA, TPM2_ALG_ECDH,
        TPM2_ALG_ECDSA, TPM2_ALG_ECMQV, TPM2_ALG_ECSCHNORR, TPM2_ALG_HMAC, TPM2_ALG_KDF1_SP800_108,
        TPM2_ALG_KDF1_SP800_56A, TPM2_ALG_KDF2, TPM2_ALG_KEYEDHASH, TPM2_ALG_MGF1, TPM2_ALG_NULL,
        TPM2_ALG_OAEP, TPM2_ALG_RSA, TPM2_ALG_RSAES, TPM2_ALG_RSAPSS, TPM2_ALG_RSASSA,
        TPM2_ALG_SM2, TPM2_ALG_SM4, TPM2_ALG_SYMCIPHER, TPM2_ALG_XOR,
    },
    tss2_esys::{
        TPMT_ECC_SCHEME, TPMT_KDF_SCHEME, TPMT_KEYEDHASH_SCHEME, TPMT_PUBLIC_PARMS,
        TPMT_RSA_SCHEME, TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT,
    },
};

pub fn ensure_tpmt_sym_def_equality(expected: &TPMT_SYM_DEF, actual: &TPMT_SYM_DEF) {
    assert_eq!(
        expected.algorithm, actual.algorithm,
        "'algorithm' value in TPMT_SYM_DEF, mismatch between actual and expected",
    );

    match expected.algorithm {
        TPM2_ALG_AES => {
            let expected_key_bits = unsafe { expected.keyBits.aes };
            let expected_mode = unsafe { expected.mode.aes };
            let actual_key_bits = unsafe { actual.keyBits.aes };
            let actual_mode = unsafe { actual.mode.aes };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );

            assert_eq!(
                expected_mode, actual_mode,
                "'mode' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );
        }
        TPM2_ALG_SM4 => {
            let expected_key_bits = unsafe { expected.keyBits.sm4 };
            let expected_mode = unsafe { expected.mode.sm4 };
            let actual_key_bits = unsafe { actual.keyBits.sm4 };
            let actual_mode = unsafe { actual.mode.sm4 };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );

            assert_eq!(
                expected_mode, actual_mode,
                "'mode' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );
        }
        TPM2_ALG_CAMELLIA => {
            let expected_key_bits = unsafe { expected.keyBits.camellia };
            let expected_mode = unsafe { expected.mode.camellia };
            let actual_key_bits = unsafe { actual.keyBits.camellia };
            let actual_mode = unsafe { actual.mode.camellia };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );

            assert_eq!(
                expected_mode, actual_mode,
                "'mode' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );
        }
        TPM2_ALG_XOR => {
            let expected_key_bits = unsafe { expected.keyBits.exclusiveOr };
            let actual_key_bits = unsafe { actual.keyBits.exclusiveOr };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );
        }
        TPM2_ALG_NULL => {}
        _ => {
            panic!("Invalid algorithm in TPMT_SYM_DEF");
        }
    }
}

pub fn ensure_tpmt_sym_def_object_equality(
    expected: &TPMT_SYM_DEF_OBJECT,
    actual: &TPMT_SYM_DEF_OBJECT,
) {
    assert_eq!(
        expected.algorithm, actual.algorithm,
        "'algorithm' value in TPMT_SYM_DEF_OBJECT, mismatch between actual and expected",
    );

    match expected.algorithm {
        TPM2_ALG_AES => {
            let expected_key_bits = unsafe { expected.keyBits.aes };
            let expected_mode = unsafe { expected.mode.aes };
            let actual_key_bits = unsafe { actual.keyBits.aes };
            let actual_mode = unsafe { actual.mode.aes };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF_OBJECT, mismatch between actual and expected",
            );

            assert_eq!(
                expected_mode, actual_mode,
                "'mode' value in TPMT_SYM_DEF_OBJECT, mismatch between actual and expected",
            );
        }
        TPM2_ALG_SM4 => {
            let expected_key_bits = unsafe { expected.keyBits.sm4 };
            let expected_mode = unsafe { expected.mode.sm4 };
            let actual_key_bits = unsafe { actual.keyBits.sm4 };
            let actual_mode = unsafe { actual.mode.sm4 };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF_OBJECT, mismatch between actual and expected",
            );

            assert_eq!(
                expected_mode, actual_mode,
                "'mode' value in TPMT_SYM_DEF_OBJECT, mismatch between actual and expected",
            );
        }
        TPM2_ALG_CAMELLIA => {
            let expected_key_bits = unsafe { expected.keyBits.camellia };
            let expected_mode = unsafe { expected.mode.camellia };
            let actual_key_bits = unsafe { actual.keyBits.camellia };
            let actual_mode = unsafe { actual.mode.camellia };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF_OBJECT, mismatch between actual and expected",
            );

            assert_eq!(
                expected_mode, actual_mode,
                "'mode' value in TPMT_SYM_DEF_OBJECT, mismatch between actual and expected",
            );
        }
        TPM2_ALG_NULL => {}
        _ => {
            panic!("Invalid algorithm in TPMT_SYM_DEF_OBJECT");
        }
    }
}

pub fn ensure_tpmt_public_parms_equality(expected: &TPMT_PUBLIC_PARMS, actual: &TPMT_PUBLIC_PARMS) {
    assert_eq!(
        expected.type_, actual.type_,
        "'type_' value in TPMT_PUBLIC_PARMS, mismatch between actual and expected",
    );

    match expected.type_ {
        TPM2_ALG_RSA => {
            let expected_rsa_parms = unsafe { &expected.parameters.rsaDetail };
            let actual_rsa_parms = unsafe { &actual.parameters.rsaDetail };
            crate::common::ensure_tpms_rsa_parms_equality(expected_rsa_parms, actual_rsa_parms);
        }
        TPM2_ALG_KEYEDHASH => {
            let expected_keyed_hash_parms = unsafe { &expected.parameters.keyedHashDetail };
            let actual_keyed_hash_parms = unsafe { &actual.parameters.keyedHashDetail };
            crate::common::ensure_tpms_keyedhash_parms_equality(
                expected_keyed_hash_parms,
                actual_keyed_hash_parms,
            );
        }
        TPM2_ALG_ECC => {
            let expected_ecc_parms = unsafe { &expected.parameters.eccDetail };
            let actual_ecc_parms = unsafe { &actual.parameters.eccDetail };
            crate::common::ensure_tpms_ecc_parms_equality(expected_ecc_parms, actual_ecc_parms);
        }
        TPM2_ALG_SYMCIPHER => {
            let expected_symcipher_parms = unsafe { &expected.parameters.symDetail };
            let actual_symcipher_parms = unsafe { &actual.parameters.symDetail };
            crate::common::ensure_tpms_symcipher_parms_equality(
                expected_symcipher_parms,
                actual_symcipher_parms,
            );
        }
        _ => {
            panic!("Invalid algorithm in TPMT_PUBLIC_PARMS");
        }
    }
}

pub fn ensure_tpmt_rsa_scheme_equality(expected: &TPMT_RSA_SCHEME, actual: &TPMT_RSA_SCHEME) {
    assert_eq!(
        expected.scheme, actual.scheme,
        "'scheme' value in TPMT_RSA_SCHEME, mismatch between actual and expected",
    );

    match expected.scheme {
        TPM2_ALG_RSASSA => {
            let expected_hash_scheme = unsafe { &expected.details.rsassa };
            let actual_hash_scheme = unsafe { &actual.details.rsassa };
            crate::common::ensure_tpms_scheme_hash_equality(
                expected_hash_scheme,
                actual_hash_scheme,
            );
        }
        TPM2_ALG_RSAES => {}
        TPM2_ALG_RSAPSS => {
            let expected_hash_scheme = unsafe { &expected.details.rsapss };
            let actual_hash_scheme = unsafe { &actual.details.rsapss };
            crate::common::ensure_tpms_scheme_hash_equality(
                expected_hash_scheme,
                actual_hash_scheme,
            );
        }
        TPM2_ALG_OAEP => {
            let expected_hash_scheme = unsafe { &expected.details.oaep };
            let actual_hash_scheme = unsafe { &actual.details.oaep };
            crate::common::ensure_tpms_scheme_hash_equality(
                expected_hash_scheme,
                actual_hash_scheme,
            );
        }
        TPM2_ALG_NULL => {}
        _ => panic!("Invalid algorithm in TPMT_RSA_SCHEME"),
    }
}

pub fn ensure_tpmt_ecc_scheme_equality(expected: &TPMT_ECC_SCHEME, actual: &TPMT_ECC_SCHEME) {
    assert_eq!(
        expected.scheme, actual.scheme,
        "'scheme' value in TPMT_ECC_SCHEME, mismatch between actual and expected",
    );
    match expected.scheme {
        TPM2_ALG_ECDSA => {
            let expected_hash_scheme = unsafe { &expected.details.ecdsa };
            let actual_hash_scheme = unsafe { &actual.details.ecdsa };
            crate::common::ensure_tpms_scheme_hash_equality(
                expected_hash_scheme,
                actual_hash_scheme,
            );
        }
        TPM2_ALG_ECDH => {
            let expected_hash_scheme = unsafe { &expected.details.ecdh };
            let actual_hash_scheme = unsafe { &actual.details.ecdh };
            crate::common::ensure_tpms_scheme_hash_equality(
                expected_hash_scheme,
                actual_hash_scheme,
            );
        }
        TPM2_ALG_ECDAA => {
            let expected_ecdaa_scheme = unsafe { &expected.details.ecdaa };
            let actual_ecdaa_scheme = unsafe { &actual.details.ecdaa };
            crate::common::ensure_tpms_scheme_ecdaa_equality(
                expected_ecdaa_scheme,
                actual_ecdaa_scheme,
            );
        }
        TPM2_ALG_SM2 => {
            let expected_hash_scheme = unsafe { &expected.details.sm2 };
            let actual_hash_scheme = unsafe { &actual.details.sm2 };
            crate::common::ensure_tpms_scheme_hash_equality(
                expected_hash_scheme,
                actual_hash_scheme,
            );
        }
        TPM2_ALG_ECSCHNORR => {
            let expected_hash_scheme = unsafe { &expected.details.ecschnorr };
            let actual_hash_scheme = unsafe { &actual.details.ecschnorr };
            crate::common::ensure_tpms_scheme_hash_equality(
                expected_hash_scheme,
                actual_hash_scheme,
            );
        }
        TPM2_ALG_ECMQV => {
            let expected_hash_scheme = unsafe { &expected.details.ecmqv };
            let actual_hash_scheme = unsafe { &actual.details.ecmqv };
            crate::common::ensure_tpms_scheme_hash_equality(
                expected_hash_scheme,
                actual_hash_scheme,
            );
        }
        TPM2_ALG_NULL => {}
        _ => panic!("Invalid algorithm in TPMT_ECC_SCHEME"),
    }
}

pub fn ensure_tpmt_keyedhash_scheme_equality(
    expected: &TPMT_KEYEDHASH_SCHEME,
    actual: &TPMT_KEYEDHASH_SCHEME,
) {
    assert_eq!(
        expected.scheme, actual.scheme,
        "'scheme' value in TPMT_KEYEDHASH_SCHEME, mismatch between actual and expected",
    );
    match expected.scheme {
        TPM2_ALG_XOR => {
            let expected_xor_scheme = unsafe { &expected.details.exclusiveOr };
            let actual_xor_scheme = unsafe { &actual.details.exclusiveOr };
            crate::common::ensure_tpms_scheme_xor_equality(expected_xor_scheme, actual_xor_scheme);
        }
        TPM2_ALG_HMAC => {
            let expected_hmac_scheme = unsafe { &expected.details.hmac };
            let actual_hmac_scheme = unsafe { &actual.details.hmac };
            crate::common::ensure_tpms_scheme_hmac_equality(
                expected_hmac_scheme,
                actual_hmac_scheme,
            );
        }
        TPM2_ALG_NULL => {}
        _ => panic!("Invalid algorithm in TPMT_KEYEDHASH_SCHEME"),
    }
}

pub fn ensure_tpmt_kdf_scheme_equality(expected: &TPMT_KDF_SCHEME, actual: &TPMT_KDF_SCHEME) {
    assert_eq!(
        expected.scheme, actual.scheme,
        "'scheme' value in TPMT_KDF_SCHEME, mismatch between actual and expected",
    );

    match expected.scheme {
        TPM2_ALG_KDF1_SP800_56A => {
            let expected_scheme = unsafe { &expected.details.kdf1_sp800_56a };
            let actual_scheme = unsafe { &actual.details.kdf1_sp800_56a };
            crate::common::ensure_tpms_scheme_hash_equality(expected_scheme, actual_scheme);
        }
        TPM2_ALG_KDF2 => {
            let expected_scheme = unsafe { &expected.details.kdf2 };
            let actual_scheme = unsafe { &actual.details.kdf2 };
            crate::common::ensure_tpms_scheme_hash_equality(expected_scheme, actual_scheme);
        }
        TPM2_ALG_KDF1_SP800_108 => {
            let expected_scheme = unsafe { &expected.details.kdf1_sp800_108 };
            let actual_scheme = unsafe { &actual.details.kdf1_sp800_108 };
            crate::common::ensure_tpms_scheme_hash_equality(expected_scheme, actual_scheme);
        }
        TPM2_ALG_MGF1 => {
            let expected_scheme = unsafe { &expected.details.mgf1 };
            let actual_scheme = unsafe { &actual.details.mgf1 };
            crate::common::ensure_tpms_scheme_hash_equality(expected_scheme, actual_scheme);
        }
        TPM2_ALG_NULL => {}
        _ => panic!("Invalid algorithm in TPMT_KDF_SCHEME"),
    }
}
