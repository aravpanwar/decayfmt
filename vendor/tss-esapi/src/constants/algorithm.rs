// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::tss::{
        TPM2_ALG_AES, TPM2_ALG_CAMELLIA, TPM2_ALG_CBC, TPM2_ALG_CFB, TPM2_ALG_CMAC, TPM2_ALG_CTR,
        TPM2_ALG_ECB, TPM2_ALG_ECC, TPM2_ALG_ECDAA, TPM2_ALG_ECDH, TPM2_ALG_ECDSA, TPM2_ALG_ECMQV,
        TPM2_ALG_ECSCHNORR, TPM2_ALG_ERROR, TPM2_ALG_HMAC, TPM2_ALG_KDF1_SP800_108,
        TPM2_ALG_KDF1_SP800_56A, TPM2_ALG_KDF2, TPM2_ALG_KEYEDHASH, TPM2_ALG_MGF1, TPM2_ALG_NULL,
        TPM2_ALG_OAEP, TPM2_ALG_OFB, TPM2_ALG_RSA, TPM2_ALG_RSAES, TPM2_ALG_RSAPSS,
        TPM2_ALG_RSASSA, TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA3_256,
        TPM2_ALG_SHA3_384, TPM2_ALG_SHA3_512, TPM2_ALG_SHA512, TPM2_ALG_SM2, TPM2_ALG_SM3_256,
        TPM2_ALG_SM4, TPM2_ALG_SYMCIPHER, TPM2_ALG_TDES, TPM2_ALG_XOR,
    },
    tss2_esys::TPM2_ALG_ID,
    Error, Result, WrapperErrorKind,
};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;
#[derive(FromPrimitive, ToPrimitive, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlgorithmIdentifier {
    Aes = TPM2_ALG_AES,
    Camellia = TPM2_ALG_CAMELLIA,
    Cbc = TPM2_ALG_CBC,
    Cfb = TPM2_ALG_CFB,
    Ctr = TPM2_ALG_CTR,
    Ecb = TPM2_ALG_ECB,
    Ecc = TPM2_ALG_ECC,
    EcDaa = TPM2_ALG_ECDAA,
    EcDh = TPM2_ALG_ECDH,
    EcDsa = TPM2_ALG_ECDSA,
    EcMqv = TPM2_ALG_ECMQV,
    EcSchnorr = TPM2_ALG_ECSCHNORR,
    Error = TPM2_ALG_ERROR,
    Hmac = TPM2_ALG_HMAC,
    Kdf1Sp800_108 = TPM2_ALG_KDF1_SP800_108,
    Kdf1Sp800_56a = TPM2_ALG_KDF1_SP800_56A,
    Kdf2 = TPM2_ALG_KDF2,
    KeyedHash = TPM2_ALG_KEYEDHASH,
    Mgf1 = TPM2_ALG_MGF1,
    Null = TPM2_ALG_NULL,
    Oaep = TPM2_ALG_OAEP,
    Ofb = TPM2_ALG_OFB,
    Rsa = TPM2_ALG_RSA,
    RsaEs = TPM2_ALG_RSAES,
    RsaPss = TPM2_ALG_RSAPSS,
    RsaSsa = TPM2_ALG_RSASSA,
    Sha1 = TPM2_ALG_SHA1,
    Sha256 = TPM2_ALG_SHA256,
    Sha384 = TPM2_ALG_SHA384,
    Sha3_256 = TPM2_ALG_SHA3_256,
    Sha3_384 = TPM2_ALG_SHA3_384,
    Sha3_512 = TPM2_ALG_SHA3_512,
    Sha512 = TPM2_ALG_SHA512,
    Sm2 = TPM2_ALG_SM2,
    Sm3_256 = TPM2_ALG_SM3_256,
    Sm4 = TPM2_ALG_SM4,
    SymCipher = TPM2_ALG_SYMCIPHER,
    Tdes = TPM2_ALG_TDES,
    Xor = TPM2_ALG_XOR,
    Cmac = TPM2_ALG_CMAC,
}

impl TryFrom<TPM2_ALG_ID> for AlgorithmIdentifier {
    type Error = Error;
    fn try_from(tpm_alg_id: TPM2_ALG_ID) -> Result<AlgorithmIdentifier> {
        AlgorithmIdentifier::from_u16(tpm_alg_id).ok_or_else(|| {
            error!(
                "Value = {} did not match any algorithm identifier",
                tpm_alg_id
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

impl From<AlgorithmIdentifier> for TPM2_ALG_ID {
    fn from(algorithm: AlgorithmIdentifier) -> TPM2_ALG_ID {
        // The values are well defined so this cannot fail.
        algorithm.to_u16().unwrap()
    }
}
