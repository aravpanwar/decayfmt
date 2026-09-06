// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::constants::{
    tss::{
        TPM2_ALG_AES, TPM2_ALG_CAMELLIA, TPM2_ALG_CBC, TPM2_ALG_CFB, TPM2_ALG_CMAC, TPM2_ALG_CTR,
        TPM2_ALG_ECB, TPM2_ALG_ECC, TPM2_ALG_ECDAA, TPM2_ALG_ECDH, TPM2_ALG_ECDSA, TPM2_ALG_ECMQV,
        TPM2_ALG_ECSCHNORR, TPM2_ALG_ERROR, TPM2_ALG_HMAC, TPM2_ALG_KDF1_SP800_108,
        TPM2_ALG_KDF1_SP800_56A, TPM2_ALG_KDF2, TPM2_ALG_KEYEDHASH, TPM2_ALG_MGF1, TPM2_ALG_NULL,
        TPM2_ALG_OAEP, TPM2_ALG_OFB, TPM2_ALG_RSA, TPM2_ALG_RSAES, TPM2_ALG_RSAPSS,
        TPM2_ALG_RSASSA, TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA3_256,
        TPM2_ALG_SHA3_384, TPM2_ALG_SHA3_512, TPM2_ALG_SHA512, TPM2_ALG_SM2, TPM2_ALG_SM3_256,
        TPM2_ALG_SM4, TPM2_ALG_SYMCIPHER, TPM2_ALG_TDES, TPM2_ALG_XOR,
    },
    AlgorithmIdentifier,
};
macro_rules! test_conversion {
    ($tpm_alg_id:ident, $algorithm:ident) => {
        assert_eq!($tpm_alg_id, AlgorithmIdentifier::$algorithm.into());
        assert_eq!(
            AlgorithmIdentifier::$algorithm,
            AlgorithmIdentifier::try_from($tpm_alg_id).expect(&format!(
                "Failed to convert tpm_alg_id for {}",
                stringify!($tpm_alg_id)
            ))
        );
    };
}
#[test]
fn test_algorithm_conversion() {
    test_conversion!(TPM2_ALG_AES, Aes);
    test_conversion!(TPM2_ALG_CAMELLIA, Camellia);
    test_conversion!(TPM2_ALG_CBC, Cbc);
    test_conversion!(TPM2_ALG_CFB, Cfb);
    test_conversion!(TPM2_ALG_CMAC, Cmac);
    test_conversion!(TPM2_ALG_CTR, Ctr);
    test_conversion!(TPM2_ALG_ECB, Ecb);
    test_conversion!(TPM2_ALG_ECC, Ecc);
    test_conversion!(TPM2_ALG_ECDAA, EcDaa);
    test_conversion!(TPM2_ALG_ECDH, EcDh);
    test_conversion!(TPM2_ALG_ECDSA, EcDsa);
    test_conversion!(TPM2_ALG_ECMQV, EcMqv);
    test_conversion!(TPM2_ALG_ECSCHNORR, EcSchnorr);
    test_conversion!(TPM2_ALG_ERROR, Error);
    test_conversion!(TPM2_ALG_HMAC, Hmac);
    test_conversion!(TPM2_ALG_KDF1_SP800_108, Kdf1Sp800_108);
    test_conversion!(TPM2_ALG_KDF1_SP800_56A, Kdf1Sp800_56a);
    test_conversion!(TPM2_ALG_KDF2, Kdf2);
    test_conversion!(TPM2_ALG_KEYEDHASH, KeyedHash);
    test_conversion!(TPM2_ALG_MGF1, Mgf1);
    test_conversion!(TPM2_ALG_NULL, Null);
    test_conversion!(TPM2_ALG_OAEP, Oaep);
    test_conversion!(TPM2_ALG_OFB, Ofb);
    test_conversion!(TPM2_ALG_RSA, Rsa);
    test_conversion!(TPM2_ALG_RSAES, RsaEs);
    test_conversion!(TPM2_ALG_RSAPSS, RsaPss);
    test_conversion!(TPM2_ALG_RSASSA, RsaSsa);
    test_conversion!(TPM2_ALG_SHA1, Sha1);
    test_conversion!(TPM2_ALG_SHA256, Sha256);
    test_conversion!(TPM2_ALG_SHA384, Sha384);
    test_conversion!(TPM2_ALG_SHA3_256, Sha3_256);
    test_conversion!(TPM2_ALG_SHA3_384, Sha3_384);
    test_conversion!(TPM2_ALG_SHA3_512, Sha3_512);
    test_conversion!(TPM2_ALG_SHA512, Sha512);
    test_conversion!(TPM2_ALG_SM2, Sm2);
    test_conversion!(TPM2_ALG_SM3_256, Sm3_256);
    test_conversion!(TPM2_ALG_SM4, Sm4);
    test_conversion!(TPM2_ALG_SYMCIPHER, SymCipher);
    test_conversion!(TPM2_ALG_TDES, Tdes);
    test_conversion!(TPM2_ALG_XOR, Xor);
}
