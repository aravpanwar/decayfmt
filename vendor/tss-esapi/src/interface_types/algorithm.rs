// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::AlgorithmIdentifier,
    tss2_esys::{
        TPMI_ALG_ASYM, TPMI_ALG_ECC_SCHEME, TPMI_ALG_HASH, TPMI_ALG_KDF, TPMI_ALG_KEYEDHASH_SCHEME,
        TPMI_ALG_PUBLIC, TPMI_ALG_RSA_DECRYPT, TPMI_ALG_RSA_SCHEME, TPMI_ALG_SIG_SCHEME,
        TPMI_ALG_SYM, TPMI_ALG_SYM_MODE, TPMI_ALG_SYM_OBJECT,
    },
    Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
/// Enum containing the supported hash algorithms
///
/// # Details
/// This corresponds to TPMI_ALG_HASH interface type.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum HashingAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Null,
}

impl From<HashingAlgorithm> for AlgorithmIdentifier {
    fn from(hashing_algorithm: HashingAlgorithm) -> Self {
        match hashing_algorithm {
            HashingAlgorithm::Sha1 => AlgorithmIdentifier::Sha1,
            HashingAlgorithm::Sha256 => AlgorithmIdentifier::Sha256,
            HashingAlgorithm::Sha384 => AlgorithmIdentifier::Sha384,
            HashingAlgorithm::Sha512 => AlgorithmIdentifier::Sha512,
            HashingAlgorithm::Sm3_256 => AlgorithmIdentifier::Sm3_256,
            HashingAlgorithm::Sha3_256 => AlgorithmIdentifier::Sha3_256,
            HashingAlgorithm::Sha3_384 => AlgorithmIdentifier::Sha3_384,
            HashingAlgorithm::Sha3_512 => AlgorithmIdentifier::Sha3_512,
            HashingAlgorithm::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for HashingAlgorithm {
    type Error = Error;

    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::Sha1 => Ok(HashingAlgorithm::Sha1),
            AlgorithmIdentifier::Sha256 => Ok(HashingAlgorithm::Sha256),
            AlgorithmIdentifier::Sha384 => Ok(HashingAlgorithm::Sha384),
            AlgorithmIdentifier::Sha512 => Ok(HashingAlgorithm::Sha512),
            AlgorithmIdentifier::Sm3_256 => Ok(HashingAlgorithm::Sm3_256),
            AlgorithmIdentifier::Sha3_256 => Ok(HashingAlgorithm::Sha3_256),
            AlgorithmIdentifier::Sha3_384 => Ok(HashingAlgorithm::Sha3_384),
            AlgorithmIdentifier::Sha3_512 => Ok(HashingAlgorithm::Sha3_512),
            AlgorithmIdentifier::Null => Ok(HashingAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<HashingAlgorithm> for TPMI_ALG_HASH {
    fn from(hashing_algorithm: HashingAlgorithm) -> Self {
        AlgorithmIdentifier::from(hashing_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_HASH> for HashingAlgorithm {
    type Error = Error;

    fn try_from(tpmi_alg_hash: TPMI_ALG_HASH) -> Result<Self> {
        HashingAlgorithm::try_from(AlgorithmIdentifier::try_from(tpmi_alg_hash)?)
    }
}

/// Enum containing the supported keyed hash scheme
///
/// # Details
/// This corresponds to TPMI_ALG_KEYEDHASH_SCHEME interface type.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyedHashSchemeAlgorithm {
    Hmac,
    Xor,
    Null,
}

impl From<KeyedHashSchemeAlgorithm> for AlgorithmIdentifier {
    fn from(keyed_hash_scheme: KeyedHashSchemeAlgorithm) -> Self {
        match keyed_hash_scheme {
            KeyedHashSchemeAlgorithm::Hmac => AlgorithmIdentifier::Hmac,
            KeyedHashSchemeAlgorithm::Xor => AlgorithmIdentifier::Xor,
            KeyedHashSchemeAlgorithm::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for KeyedHashSchemeAlgorithm {
    type Error = Error;
    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::Hmac => Ok(KeyedHashSchemeAlgorithm::Hmac),
            AlgorithmIdentifier::Xor => Ok(KeyedHashSchemeAlgorithm::Xor),
            AlgorithmIdentifier::Null => Ok(KeyedHashSchemeAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<KeyedHashSchemeAlgorithm> for TPMI_ALG_KEYEDHASH_SCHEME {
    fn from(keyed_hash_scheme: KeyedHashSchemeAlgorithm) -> Self {
        AlgorithmIdentifier::from(keyed_hash_scheme).into()
    }
}

impl TryFrom<TPMI_ALG_KEYEDHASH_SCHEME> for KeyedHashSchemeAlgorithm {
    type Error = Error;
    fn try_from(tpmi_alg_keyed_hash_scheme: TPMI_ALG_KEYEDHASH_SCHEME) -> Result<Self> {
        KeyedHashSchemeAlgorithm::try_from(AlgorithmIdentifier::try_from(
            tpmi_alg_keyed_hash_scheme,
        )?)
    }
}

/// Enum containing key derivation functions interface type.
///
/// # Details this corresponds to the TPMI_ALG_KDF
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyDerivationFunction {
    Kdf1Sp800_56a,
    Kdf2,
    Kdf1Sp800_108,
    Mgf1,
    Null,
}

impl From<KeyDerivationFunction> for AlgorithmIdentifier {
    fn from(key_derivation_function: KeyDerivationFunction) -> Self {
        match key_derivation_function {
            KeyDerivationFunction::Kdf1Sp800_56a => AlgorithmIdentifier::Kdf1Sp800_56a,
            KeyDerivationFunction::Kdf2 => AlgorithmIdentifier::Kdf2,
            KeyDerivationFunction::Kdf1Sp800_108 => AlgorithmIdentifier::Kdf1Sp800_108,
            KeyDerivationFunction::Mgf1 => AlgorithmIdentifier::Mgf1,
            KeyDerivationFunction::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for KeyDerivationFunction {
    type Error = Error;

    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::Kdf1Sp800_56a => Ok(KeyDerivationFunction::Kdf1Sp800_56a),
            AlgorithmIdentifier::Kdf2 => Ok(KeyDerivationFunction::Kdf2),
            AlgorithmIdentifier::Kdf1Sp800_108 => Ok(KeyDerivationFunction::Kdf1Sp800_108),
            AlgorithmIdentifier::Mgf1 => Ok(KeyDerivationFunction::Mgf1),
            AlgorithmIdentifier::Null => Ok(KeyDerivationFunction::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<KeyDerivationFunction> for TPMI_ALG_KDF {
    fn from(key_derivation_function: KeyDerivationFunction) -> Self {
        AlgorithmIdentifier::from(key_derivation_function).into()
    }
}

impl TryFrom<TPMI_ALG_KDF> for KeyDerivationFunction {
    type Error = Error;

    fn try_from(tpmi_alg_kdf: TPMI_ALG_KDF) -> Result<Self> {
        KeyDerivationFunction::try_from(AlgorithmIdentifier::try_from(tpmi_alg_kdf)?)
    }
}

/// Enum representing the symmetric algorithm interface type.
///
/// # Details
/// This corresponds to TPMI_ALG_SYM.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SymmetricAlgorithm {
    Tdes,
    Aes,
    Sm4,
    Camellia,
    Xor,
    Null,
}

impl From<SymmetricAlgorithm> for AlgorithmIdentifier {
    fn from(symmetric_algorithm: SymmetricAlgorithm) -> Self {
        match symmetric_algorithm {
            SymmetricAlgorithm::Tdes => AlgorithmIdentifier::Tdes,
            SymmetricAlgorithm::Aes => AlgorithmIdentifier::Aes,
            SymmetricAlgorithm::Sm4 => AlgorithmIdentifier::Sm4,
            SymmetricAlgorithm::Camellia => AlgorithmIdentifier::Camellia,
            SymmetricAlgorithm::Xor => AlgorithmIdentifier::Xor,
            SymmetricAlgorithm::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for SymmetricAlgorithm {
    type Error = Error;
    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::Tdes => Ok(SymmetricAlgorithm::Tdes),
            AlgorithmIdentifier::Aes => Ok(SymmetricAlgorithm::Aes),
            AlgorithmIdentifier::Sm4 => Ok(SymmetricAlgorithm::Sm4),
            AlgorithmIdentifier::Camellia => Ok(SymmetricAlgorithm::Camellia),
            AlgorithmIdentifier::Xor => Ok(SymmetricAlgorithm::Xor),
            AlgorithmIdentifier::Null => Ok(SymmetricAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<SymmetricAlgorithm> for TPMI_ALG_SYM {
    fn from(symmetric_algorithm: SymmetricAlgorithm) -> Self {
        AlgorithmIdentifier::from(symmetric_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_SYM> for SymmetricAlgorithm {
    type Error = Error;

    fn try_from(tpmi_alg_sym: TPMI_ALG_SYM) -> Result<Self> {
        SymmetricAlgorithm::try_from(AlgorithmIdentifier::try_from(tpmi_alg_sym)?)
    }
}

/// Enum representing the symmetric mode interface type.
///
/// # Details
/// Corresponds to TPMI_ALG_SYM_MODE.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SymmetricMode {
    Ctr,
    Ofb,
    Cbc,
    Cfb,
    Ecb,
    Null,
}

impl From<SymmetricMode> for AlgorithmIdentifier {
    fn from(symmetric_mode: SymmetricMode) -> Self {
        match symmetric_mode {
            SymmetricMode::Ctr => AlgorithmIdentifier::Ctr,
            SymmetricMode::Ofb => AlgorithmIdentifier::Ofb,
            SymmetricMode::Cbc => AlgorithmIdentifier::Cbc,
            SymmetricMode::Cfb => AlgorithmIdentifier::Cfb,
            SymmetricMode::Ecb => AlgorithmIdentifier::Ecb,
            SymmetricMode::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for SymmetricMode {
    type Error = Error;
    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<SymmetricMode> {
        match algorithm_identifier {
            AlgorithmIdentifier::Ctr => Ok(SymmetricMode::Ctr),
            AlgorithmIdentifier::Ofb => Ok(SymmetricMode::Ofb),
            AlgorithmIdentifier::Cbc => Ok(SymmetricMode::Cbc),
            AlgorithmIdentifier::Cfb => Ok(SymmetricMode::Cfb),
            AlgorithmIdentifier::Ecb => Ok(SymmetricMode::Ecb),
            AlgorithmIdentifier::Null => Ok(SymmetricMode::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<SymmetricMode> for TPMI_ALG_SYM_MODE {
    fn from(symmetric_mode: SymmetricMode) -> Self {
        AlgorithmIdentifier::from(symmetric_mode).into()
    }
}

impl TryFrom<TPMI_ALG_SYM_MODE> for SymmetricMode {
    type Error = Error;

    fn try_from(tpmi_alg_sym_mode: TPMI_ALG_SYM_MODE) -> Result<Self> {
        SymmetricMode::try_from(AlgorithmIdentifier::try_from(tpmi_alg_sym_mode)?)
    }
}

/// Enum representing the asymmetric algorithm interface type.
///
/// # Details
/// Use [crate::abstraction::AsymmetricAlgorithmSelection] instead where possible.
/// This corresponds to TPMI_ALG_ASYM.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AsymmetricAlgorithm {
    Rsa,
    Ecc,
    Null,
}

impl From<AsymmetricAlgorithm> for AlgorithmIdentifier {
    fn from(asymmetric_algorithm: AsymmetricAlgorithm) -> Self {
        match asymmetric_algorithm {
            AsymmetricAlgorithm::Rsa => AlgorithmIdentifier::Rsa,
            AsymmetricAlgorithm::Ecc => AlgorithmIdentifier::Ecc,
            AsymmetricAlgorithm::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for AsymmetricAlgorithm {
    type Error = Error;
    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::Rsa => Ok(AsymmetricAlgorithm::Rsa),
            AlgorithmIdentifier::Ecc => Ok(AsymmetricAlgorithm::Ecc),
            AlgorithmIdentifier::Null => Ok(AsymmetricAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<AsymmetricAlgorithm> for TPMI_ALG_ASYM {
    fn from(asymmetric_algorithm: AsymmetricAlgorithm) -> Self {
        AlgorithmIdentifier::from(asymmetric_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_ASYM> for AsymmetricAlgorithm {
    type Error = Error;
    fn try_from(tpmi_alg_sym: TPMI_ALG_ASYM) -> Result<Self> {
        AsymmetricAlgorithm::try_from(AlgorithmIdentifier::try_from(tpmi_alg_sym)?)
    }
}

/// Enum representing the signature scheme interface type.
///
/// # Details
/// This corresponds to TPMI_ALG_SIG_SCHEME
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SignatureSchemeAlgorithm {
    RsaSsa,
    RsaPss,
    EcDsa,
    EcDaa,
    Sm2,
    EcSchnorr,
    Hmac,
    Null,
}

impl From<SignatureSchemeAlgorithm> for AlgorithmIdentifier {
    fn from(signature_scheme_algorithm: SignatureSchemeAlgorithm) -> Self {
        match signature_scheme_algorithm {
            SignatureSchemeAlgorithm::RsaSsa => AlgorithmIdentifier::RsaSsa,
            SignatureSchemeAlgorithm::RsaPss => AlgorithmIdentifier::RsaPss,
            SignatureSchemeAlgorithm::EcDsa => AlgorithmIdentifier::EcDsa,
            SignatureSchemeAlgorithm::EcDaa => AlgorithmIdentifier::EcDaa,
            SignatureSchemeAlgorithm::Sm2 => AlgorithmIdentifier::Sm2,
            SignatureSchemeAlgorithm::EcSchnorr => AlgorithmIdentifier::EcSchnorr,
            SignatureSchemeAlgorithm::Hmac => AlgorithmIdentifier::Hmac,
            SignatureSchemeAlgorithm::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for SignatureSchemeAlgorithm {
    type Error = Error;
    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::RsaSsa => Ok(SignatureSchemeAlgorithm::RsaSsa),
            AlgorithmIdentifier::RsaPss => Ok(SignatureSchemeAlgorithm::RsaPss),
            AlgorithmIdentifier::EcDsa => Ok(SignatureSchemeAlgorithm::EcDsa),
            AlgorithmIdentifier::EcDaa => Ok(SignatureSchemeAlgorithm::EcDaa),
            AlgorithmIdentifier::Sm2 => Ok(SignatureSchemeAlgorithm::Sm2),
            AlgorithmIdentifier::EcSchnorr => Ok(SignatureSchemeAlgorithm::EcSchnorr),
            AlgorithmIdentifier::Hmac => Ok(SignatureSchemeAlgorithm::Hmac),
            AlgorithmIdentifier::Null => Ok(SignatureSchemeAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<SignatureSchemeAlgorithm> for TPMI_ALG_SIG_SCHEME {
    fn from(signature_scheme_algorithm: SignatureSchemeAlgorithm) -> Self {
        AlgorithmIdentifier::from(signature_scheme_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_SIG_SCHEME> for SignatureSchemeAlgorithm {
    type Error = Error;
    fn try_from(tpmi_alg_sym_scheme: TPMI_ALG_SIG_SCHEME) -> Result<Self> {
        SignatureSchemeAlgorithm::try_from(AlgorithmIdentifier::try_from(tpmi_alg_sym_scheme)?)
    }
}

// A convenience conversion into AsymmetricAlgorithm
// that is associated with the signature scheme.
impl TryFrom<SignatureSchemeAlgorithm> for AsymmetricAlgorithm {
    type Error = Error;
    fn try_from(signature_scheme: SignatureSchemeAlgorithm) -> Result<Self> {
        match signature_scheme {
            SignatureSchemeAlgorithm::RsaSsa => Ok(AsymmetricAlgorithm::Rsa),
            SignatureSchemeAlgorithm::RsaPss => Ok(AsymmetricAlgorithm::Rsa),
            SignatureSchemeAlgorithm::EcDsa => Ok(AsymmetricAlgorithm::Ecc),
            SignatureSchemeAlgorithm::EcDaa => Ok(AsymmetricAlgorithm::Ecc),
            SignatureSchemeAlgorithm::Sm2 => Ok(AsymmetricAlgorithm::Ecc),
            SignatureSchemeAlgorithm::EcSchnorr => Ok(AsymmetricAlgorithm::Ecc),
            _ => {
                // HMAC is for symmetric algorithms
                //
                // Null could be converted into AsymmetricAlgorithm::Null
                // but I do not know if that is useful.
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}

/// Enum repsenting the symmetric object inetrface type.
///
/// # Details
/// This corresponds to TPMI_ALG_SYM_OBJECT
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SymmetricObject {
    Tdes,
    Aes,
    Sm4,
    Camellia,
    Null,
}

impl From<SymmetricObject> for AlgorithmIdentifier {
    fn from(symmetric_object: SymmetricObject) -> Self {
        match symmetric_object {
            SymmetricObject::Tdes => AlgorithmIdentifier::Tdes,
            SymmetricObject::Aes => AlgorithmIdentifier::Aes,
            SymmetricObject::Sm4 => AlgorithmIdentifier::Sm4,
            SymmetricObject::Camellia => AlgorithmIdentifier::Camellia,
            SymmetricObject::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for SymmetricObject {
    type Error = Error;
    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::Tdes => Ok(SymmetricObject::Tdes),
            AlgorithmIdentifier::Aes => Ok(SymmetricObject::Aes),
            AlgorithmIdentifier::Sm4 => Ok(SymmetricObject::Sm4),
            AlgorithmIdentifier::Camellia => Ok(SymmetricObject::Camellia),
            AlgorithmIdentifier::Null => Ok(SymmetricObject::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<SymmetricObject> for TPMI_ALG_SYM_OBJECT {
    fn from(symmetric_object: SymmetricObject) -> Self {
        AlgorithmIdentifier::from(symmetric_object).into()
    }
}

impl TryFrom<TPMI_ALG_SYM_OBJECT> for SymmetricObject {
    type Error = Error;

    fn try_from(tpmi_alg_sym_object: TPMI_ALG_SYM_OBJECT) -> Result<Self> {
        SymmetricObject::try_from(AlgorithmIdentifier::try_from(tpmi_alg_sym_object)?)
    }
}

/// Enum repsenting the public interface type
///
/// # Details
/// This corresponds to TPMI_ALG_PUBLIC
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PublicAlgorithm {
    Rsa,
    KeyedHash,
    Ecc,
    SymCipher,
}

impl From<PublicAlgorithm> for AlgorithmIdentifier {
    fn from(public_algorithm: PublicAlgorithm) -> Self {
        match public_algorithm {
            PublicAlgorithm::Rsa => AlgorithmIdentifier::Rsa,
            PublicAlgorithm::KeyedHash => AlgorithmIdentifier::KeyedHash,
            PublicAlgorithm::Ecc => AlgorithmIdentifier::Ecc,
            PublicAlgorithm::SymCipher => AlgorithmIdentifier::SymCipher,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for PublicAlgorithm {
    type Error = Error;
    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::Rsa => Ok(PublicAlgorithm::Rsa),
            AlgorithmIdentifier::KeyedHash => Ok(PublicAlgorithm::KeyedHash),
            AlgorithmIdentifier::Ecc => Ok(PublicAlgorithm::Ecc),
            AlgorithmIdentifier::SymCipher => Ok(PublicAlgorithm::SymCipher),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<PublicAlgorithm> for TPMI_ALG_PUBLIC {
    fn from(public_algorithm: PublicAlgorithm) -> Self {
        AlgorithmIdentifier::from(public_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_PUBLIC> for PublicAlgorithm {
    type Error = Error;

    fn try_from(tpmi_alg_public: TPMI_ALG_PUBLIC) -> Result<Self> {
        PublicAlgorithm::try_from(AlgorithmIdentifier::try_from(tpmi_alg_public)?)
    }
}

/// Enum repsenting the rsa scheme interface type
///
/// # Details
/// This corresponds to TPMI_ALG_RSA_SCHEME
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RsaSchemeAlgorithm {
    RsaSsa,
    RsaEs,
    RsaPss,
    Oaep,
    Null,
}

impl From<RsaSchemeAlgorithm> for AlgorithmIdentifier {
    fn from(rsa_scheme_algorithm: RsaSchemeAlgorithm) -> Self {
        match rsa_scheme_algorithm {
            RsaSchemeAlgorithm::RsaSsa => AlgorithmIdentifier::RsaSsa,
            RsaSchemeAlgorithm::RsaEs => AlgorithmIdentifier::RsaEs,
            RsaSchemeAlgorithm::RsaPss => AlgorithmIdentifier::RsaPss,
            RsaSchemeAlgorithm::Oaep => AlgorithmIdentifier::Oaep,
            RsaSchemeAlgorithm::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for RsaSchemeAlgorithm {
    type Error = Error;

    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::RsaSsa => Ok(RsaSchemeAlgorithm::RsaSsa),
            AlgorithmIdentifier::RsaEs => Ok(RsaSchemeAlgorithm::RsaEs),
            AlgorithmIdentifier::RsaPss => Ok(RsaSchemeAlgorithm::RsaPss),
            AlgorithmIdentifier::Oaep => Ok(RsaSchemeAlgorithm::Oaep),
            AlgorithmIdentifier::Null => Ok(RsaSchemeAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<RsaSchemeAlgorithm> for TPMI_ALG_RSA_SCHEME {
    fn from(rsa_scheme_algorithm: RsaSchemeAlgorithm) -> Self {
        AlgorithmIdentifier::from(rsa_scheme_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_RSA_SCHEME> for RsaSchemeAlgorithm {
    type Error = Error;

    fn try_from(tpmi_alg_rsa_scheme: TPMI_ALG_RSA_SCHEME) -> Result<Self> {
        RsaSchemeAlgorithm::try_from(AlgorithmIdentifier::try_from(tpmi_alg_rsa_scheme)?)
    }
}

/// Enum repsenting the rsa scheme interface type
///
/// # Details
/// This corresponds to TPMI_ALG_ECC_SCHEME
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum EccSchemeAlgorithm {
    EcDsa,
    EcDh,
    EcDaa,
    Sm2,
    EcSchnorr,
    EcMqv,
    Null,
}

impl From<EccSchemeAlgorithm> for AlgorithmIdentifier {
    fn from(ecc_scheme_algorithm: EccSchemeAlgorithm) -> Self {
        match ecc_scheme_algorithm {
            EccSchemeAlgorithm::EcDsa => AlgorithmIdentifier::EcDsa,
            EccSchemeAlgorithm::EcDh => AlgorithmIdentifier::EcDh,
            EccSchemeAlgorithm::EcDaa => AlgorithmIdentifier::EcDaa,
            EccSchemeAlgorithm::Sm2 => AlgorithmIdentifier::Sm2,
            EccSchemeAlgorithm::EcSchnorr => AlgorithmIdentifier::EcSchnorr,
            EccSchemeAlgorithm::EcMqv => AlgorithmIdentifier::EcMqv,
            EccSchemeAlgorithm::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for EccSchemeAlgorithm {
    type Error = Error;

    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::EcDsa => Ok(EccSchemeAlgorithm::EcDsa),
            AlgorithmIdentifier::EcDh => Ok(EccSchemeAlgorithm::EcDh),
            AlgorithmIdentifier::EcDaa => Ok(EccSchemeAlgorithm::EcDaa),
            AlgorithmIdentifier::Sm2 => Ok(EccSchemeAlgorithm::Sm2),
            AlgorithmIdentifier::EcSchnorr => Ok(EccSchemeAlgorithm::EcSchnorr),
            AlgorithmIdentifier::EcMqv => Ok(EccSchemeAlgorithm::EcMqv),
            AlgorithmIdentifier::Null => Ok(EccSchemeAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<EccSchemeAlgorithm> for TPMI_ALG_ECC_SCHEME {
    fn from(ecc_scheme_algorithm: EccSchemeAlgorithm) -> Self {
        AlgorithmIdentifier::from(ecc_scheme_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_ECC_SCHEME> for EccSchemeAlgorithm {
    type Error = Error;

    fn try_from(tpmi_alg_ecc_scheme: TPMI_ALG_ECC_SCHEME) -> Result<Self> {
        EccSchemeAlgorithm::try_from(AlgorithmIdentifier::try_from(tpmi_alg_ecc_scheme)?)
    }
}

/// Enum repsenting the rsa decryption interface type
///
/// # Details
/// This corresponds to TPMI_ALG_RSA_DECRYPT
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RsaDecryptAlgorithm {
    RsaEs,
    Oaep,
    Null,
}

impl From<RsaDecryptAlgorithm> for AlgorithmIdentifier {
    fn from(rsa_decrypt_algorithm: RsaDecryptAlgorithm) -> Self {
        match rsa_decrypt_algorithm {
            RsaDecryptAlgorithm::RsaEs => AlgorithmIdentifier::RsaEs,
            RsaDecryptAlgorithm::Oaep => AlgorithmIdentifier::Oaep,
            RsaDecryptAlgorithm::Null => AlgorithmIdentifier::Null,
        }
    }
}

impl TryFrom<AlgorithmIdentifier> for RsaDecryptAlgorithm {
    type Error = Error;

    fn try_from(algorithm_identifier: AlgorithmIdentifier) -> Result<Self> {
        match algorithm_identifier {
            AlgorithmIdentifier::RsaEs => Ok(RsaDecryptAlgorithm::RsaEs),
            AlgorithmIdentifier::Oaep => Ok(RsaDecryptAlgorithm::Oaep),
            AlgorithmIdentifier::Null => Ok(RsaDecryptAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<RsaDecryptAlgorithm> for TPMI_ALG_RSA_DECRYPT {
    fn from(rsa_decrypt_algorithm: RsaDecryptAlgorithm) -> Self {
        AlgorithmIdentifier::from(rsa_decrypt_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_RSA_DECRYPT> for RsaDecryptAlgorithm {
    type Error = Error;

    fn try_from(tpmi_alg_rsa_decrypt: TPMI_ALG_RSA_DECRYPT) -> Result<Self> {
        RsaDecryptAlgorithm::try_from(AlgorithmIdentifier::try_from(tpmi_alg_rsa_decrypt)?)
    }
}
