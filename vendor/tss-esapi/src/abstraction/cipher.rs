// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::AlgorithmIdentifier,
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricAlgorithm, SymmetricMode, SymmetricObject},
        key_bits::{AesKeyBits, CamelliaKeyBits, Sm4KeyBits},
    },
    structures::{SymmetricCipherParameters, SymmetricDefinition, SymmetricDefinitionObject},
    Error, Result, WrapperErrorKind,
};
use std::convert::{TryFrom, TryInto};
/// Block cipher identifiers
///
/// Structure useful for handling an abstract representation of ciphers. Ciphers are
/// defined foremost through their symmetric algorithm and, depending on the type of that
/// algorithm, on a set of other values.
#[derive(Copy, Clone, Debug)]
pub struct Cipher {
    algorithm: SymmetricAlgorithm,
    mode: Option<SymmetricMode>,
    key_bits: Option<u16>,
    hash: Option<HashingAlgorithm>,
}

impl Cipher {
    /// Constructor for AES cipher identifier
    ///
    /// `key_bits` must be one of 128, 192 or 256.
    pub fn aes(mode: SymmetricMode, key_bits: u16) -> Result<Self> {
        match key_bits {
            128 | 192 | 256 => (),
            _ => return Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }

        Ok(Cipher {
            algorithm: SymmetricAlgorithm::Aes,
            mode: Some(mode),
            key_bits: Some(key_bits),
            hash: None,
        })
    }

    /// Constructor for Camellia cipher identifier
    ///
    /// `key_bits` must be one of 128, 192 or 256.
    pub fn camellia(mode: SymmetricMode, key_bits: u16) -> Result<Self> {
        match key_bits {
            128 | 192 | 256 => (),
            _ => return Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }

        Ok(Cipher {
            algorithm: SymmetricAlgorithm::Camellia,
            mode: Some(mode),
            key_bits: Some(key_bits),
            hash: None,
        })
    }

    /// Constructor for Triple DES cipher identifier
    ///
    /// `key_bits` must be one of 56, 112 or 168.
    pub fn tdes(mode: SymmetricMode, key_bits: u16) -> Result<Self> {
        match key_bits {
            56 | 112 | 168 => (),
            _ => return Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }

        Ok(Cipher {
            algorithm: SymmetricAlgorithm::Tdes,
            mode: Some(mode),
            key_bits: Some(key_bits),
            hash: None,
        })
    }

    /// Constructor for SM4 cipher identifier
    pub fn sm4(mode: SymmetricMode) -> Self {
        Cipher {
            algorithm: SymmetricAlgorithm::Sm4,
            mode: Some(mode),
            key_bits: Some(128),
            hash: None,
        }
    }

    /// Constructor for XOR "cipher" identifier
    pub fn xor(hash: HashingAlgorithm) -> Self {
        Cipher {
            algorithm: SymmetricAlgorithm::Xor,
            mode: None,
            key_bits: None,
            hash: Some(hash),
        }
    }

    /// Get general object type for symmetric ciphers.
    pub fn object_type() -> AlgorithmIdentifier {
        AlgorithmIdentifier::SymCipher
    }

    /// Get the cipher key length.
    pub fn key_bits(self) -> Option<u16> {
        self.key_bits
    }

    /// Get the cipher mode.
    pub fn mode(self) -> Option<SymmetricMode> {
        self.mode
    }

    /// Get the hash algorithm used with an XOR cipher
    pub fn hash(self) -> Option<HashingAlgorithm> {
        self.hash
    }

    /// Get the symmetrical algorithm for the cipher.
    pub fn algorithm(&self) -> SymmetricAlgorithm {
        self.algorithm
    }

    /// Constructor for 128 bit AES in CFB mode.
    pub fn aes_128_cfb() -> Self {
        Cipher {
            algorithm: SymmetricAlgorithm::Aes,
            mode: Some(SymmetricMode::Cfb),
            key_bits: Some(128),
            hash: None,
        }
    }

    /// Constructor for 256 bit AES in CFB mode.
    pub fn aes_256_cfb() -> Self {
        Cipher {
            algorithm: SymmetricAlgorithm::Aes,
            mode: Some(SymmetricMode::Cfb),
            key_bits: Some(256),
            hash: None,
        }
    }
}

impl TryFrom<Cipher> for SymmetricDefinition {
    type Error = Error;
    fn try_from(cipher: Cipher) -> Result<Self> {
        match cipher.algorithm {
            SymmetricAlgorithm::Aes => Ok(SymmetricDefinition::Aes {
                key_bits: cipher
                    .key_bits
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))
                    .and_then(AesKeyBits::try_from)?,
                mode: cipher
                    .mode
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))?,
            }),
            SymmetricAlgorithm::Sm4 => Ok(SymmetricDefinition::Sm4 {
                key_bits: cipher
                    .key_bits
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))
                    .and_then(Sm4KeyBits::try_from)?,
                mode: cipher
                    .mode
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))?,
            }),
            SymmetricAlgorithm::Camellia => Ok(SymmetricDefinition::Camellia {
                key_bits: cipher
                    .key_bits
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))
                    .and_then(CamelliaKeyBits::try_from)?,
                mode: cipher
                    .mode
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))?,
            }),
            SymmetricAlgorithm::Xor => Ok(SymmetricDefinition::Xor {
                hashing_algorithm: cipher
                    .hash
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))
                    .and_then(|ha| {
                        if ha != HashingAlgorithm::Null {
                            Ok(ha)
                        } else {
                            Err(Error::local_error(WrapperErrorKind::InvalidParam))
                        }
                    })?,
            }),
            SymmetricAlgorithm::Null => Ok(SymmetricDefinition::Null),
            SymmetricAlgorithm::Tdes => {
                // TODO: Investigate
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
        }
    }
}

impl TryFrom<Cipher> for SymmetricDefinitionObject {
    type Error = Error;
    fn try_from(cipher: Cipher) -> Result<Self> {
        match SymmetricObject::try_from(AlgorithmIdentifier::from(cipher.algorithm))? {
            SymmetricObject::Aes => Ok(SymmetricDefinitionObject::Aes {
                key_bits: cipher
                    .key_bits
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))
                    .and_then(AesKeyBits::try_from)?,
                mode: cipher
                    .mode
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))?,
            }),
            SymmetricObject::Sm4 => Ok(SymmetricDefinitionObject::Sm4 {
                key_bits: cipher
                    .key_bits
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))
                    .and_then(Sm4KeyBits::try_from)?,
                mode: cipher
                    .mode
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))?,
            }),
            SymmetricObject::Camellia => Ok(SymmetricDefinitionObject::Camellia {
                key_bits: cipher
                    .key_bits
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))
                    .and_then(CamelliaKeyBits::try_from)?,
                mode: cipher
                    .mode
                    .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))?,
            }),
            SymmetricObject::Null => Ok(SymmetricDefinitionObject::Null),
            SymmetricObject::Tdes => {
                // TODO investigate
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
        }
    }
}

impl TryFrom<Cipher> for SymmetricCipherParameters {
    type Error = Error;
    fn try_from(cipher: Cipher) -> Result<Self> {
        Ok(SymmetricCipherParameters::new(cipher.try_into()?))
    }
}
