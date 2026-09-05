// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricAlgorithm, SymmetricMode, SymmetricObject},
        key_bits::{AesKeyBits, CamelliaKeyBits, Sm4KeyBits},
    },
    tss2_esys::{TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT, TPMU_SYM_KEY_BITS, TPMU_SYM_MODE},
    Error, Result, WrapperErrorKind,
};
use std::convert::{TryFrom, TryInto};
/// Enum representing the symmetric algorithm definition.
///
/// # Details
/// This corresponds to TPMT_SYM_DEF.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SymmetricDefinition {
    // TODO: Investigate why TDES is not included...
    Aes {
        key_bits: AesKeyBits,
        mode: SymmetricMode,
    },
    Sm4 {
        key_bits: Sm4KeyBits,
        mode: SymmetricMode,
    },
    Camellia {
        key_bits: CamelliaKeyBits,
        mode: SymmetricMode,
    },
    Xor {
        hashing_algorithm: HashingAlgorithm,
    },
    Null,
}

impl SymmetricDefinition {
    /// Constant for the AES 128 bits CFB symmetric definition
    pub const AES_128_CFB: SymmetricDefinition = SymmetricDefinition::Aes {
        key_bits: AesKeyBits::Aes128,
        mode: SymmetricMode::Cfb,
    };

    /// Constant for the AES 128 bits CFB symmetric definition
    pub const AES_256_CFB: SymmetricDefinition = SymmetricDefinition::Aes {
        key_bits: AesKeyBits::Aes256,
        mode: SymmetricMode::Cfb,
    };
}

impl TryFrom<SymmetricDefinition> for TPMT_SYM_DEF {
    type Error = Error;
    fn try_from(symmetric_definition: SymmetricDefinition) -> Result<TPMT_SYM_DEF> {
        match symmetric_definition {
            SymmetricDefinition::Aes { key_bits, mode } => Ok(TPMT_SYM_DEF {
                algorithm: SymmetricAlgorithm::Aes.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    aes: key_bits.into(),
                },
                mode: TPMU_SYM_MODE { aes: mode.into() },
            }),
            SymmetricDefinition::Sm4 { key_bits, mode } => Ok(TPMT_SYM_DEF {
                algorithm: SymmetricAlgorithm::Sm4.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    sm4: key_bits.into(),
                },
                mode: TPMU_SYM_MODE { sm4: mode.into() },
            }),
            SymmetricDefinition::Camellia { key_bits, mode } => Ok(TPMT_SYM_DEF {
                algorithm: SymmetricAlgorithm::Camellia.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    camellia: key_bits.into(),
                },
                mode: TPMU_SYM_MODE {
                    camellia: mode.into(),
                },
            }),
            SymmetricDefinition::Xor { hashing_algorithm } => Ok(TPMT_SYM_DEF {
                algorithm: SymmetricAlgorithm::Xor.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    exclusiveOr: if hashing_algorithm != HashingAlgorithm::Null {
                        hashing_algorithm.into()
                    } else {
                        return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                    },
                },
                mode: Default::default(),
            }),
            SymmetricDefinition::Null => Ok(TPMT_SYM_DEF {
                algorithm: SymmetricAlgorithm::Null.into(),
                keyBits: Default::default(),
                mode: Default::default(),
            }),
        }
    }
}

impl TryFrom<TPMT_SYM_DEF> for SymmetricDefinition {
    type Error = Error;
    fn try_from(tpmt_sym_def: TPMT_SYM_DEF) -> Result<SymmetricDefinition> {
        match SymmetricAlgorithm::try_from(tpmt_sym_def.algorithm)? {
            SymmetricAlgorithm::Aes => Ok(SymmetricDefinition::Aes {
                key_bits: unsafe { tpmt_sym_def.keyBits.aes }.try_into()?,
                mode: unsafe { tpmt_sym_def.mode.aes }.try_into()?,
            }),
            SymmetricAlgorithm::Sm4 => Ok(SymmetricDefinition::Sm4 {
                key_bits: unsafe { tpmt_sym_def.keyBits.sm4 }.try_into()?,
                mode: unsafe { tpmt_sym_def.mode.sm4 }.try_into()?,
            }),
            SymmetricAlgorithm::Camellia => Ok(SymmetricDefinition::Camellia {
                key_bits: unsafe { tpmt_sym_def.keyBits.camellia }.try_into()?,
                mode: unsafe { tpmt_sym_def.mode.camellia }.try_into()?,
            }),
            SymmetricAlgorithm::Xor => Ok(SymmetricDefinition::Xor {
                hashing_algorithm: HashingAlgorithm::try_from(unsafe {
                    tpmt_sym_def.keyBits.exclusiveOr
                })
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
                // TODO: Investigate this...
                Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm))
            }
        }
    }
}

/// Enum representing the symmetric definition object.
///
/// # Details
/// This corresponds to TPMT_SYM_DEF_OBJECT
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymmetricDefinitionObject {
    // TDOD: Investigate why TDES is missing.
    Aes {
        key_bits: AesKeyBits,
        mode: SymmetricMode,
    },
    Sm4 {
        key_bits: Sm4KeyBits,
        mode: SymmetricMode,
    },
    Camellia {
        key_bits: CamelliaKeyBits,
        mode: SymmetricMode,
    },
    #[default]
    Null,
}

impl SymmetricDefinitionObject {
    /// Constant for the AES 128 bits CFB symmetric definition object
    pub const AES_128_CFB: SymmetricDefinitionObject = SymmetricDefinitionObject::Aes {
        key_bits: AesKeyBits::Aes128,
        mode: SymmetricMode::Cfb,
    };

    /// Constant for the AES 256 bits CFB symmetric definition object
    pub const AES_256_CFB: SymmetricDefinitionObject = SymmetricDefinitionObject::Aes {
        key_bits: AesKeyBits::Aes256,
        mode: SymmetricMode::Cfb,
    };

    // Constant for the SM4 128 bits CFB symmetric definition object
    pub const SM4_128_CFB: SymmetricDefinitionObject = SymmetricDefinitionObject::Sm4 {
        key_bits: Sm4KeyBits::Sm4_128,
        mode: SymmetricMode::Cfb,
    };

    pub(crate) fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl From<SymmetricDefinitionObject> for TPMT_SYM_DEF_OBJECT {
    fn from(symmetric_definition_object: SymmetricDefinitionObject) -> TPMT_SYM_DEF_OBJECT {
        match symmetric_definition_object {
            SymmetricDefinitionObject::Aes { key_bits, mode } => TPMT_SYM_DEF_OBJECT {
                algorithm: SymmetricAlgorithm::Aes.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    aes: key_bits.into(),
                },
                mode: TPMU_SYM_MODE { aes: mode.into() },
            },
            SymmetricDefinitionObject::Sm4 { key_bits, mode } => TPMT_SYM_DEF_OBJECT {
                algorithm: SymmetricAlgorithm::Sm4.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    sm4: key_bits.into(),
                },
                mode: TPMU_SYM_MODE { sm4: mode.into() },
            },
            SymmetricDefinitionObject::Camellia { key_bits, mode } => TPMT_SYM_DEF_OBJECT {
                algorithm: SymmetricAlgorithm::Camellia.into(),
                keyBits: TPMU_SYM_KEY_BITS {
                    camellia: key_bits.into(),
                },
                mode: TPMU_SYM_MODE {
                    camellia: mode.into(),
                },
            },
            SymmetricDefinitionObject::Null => TPMT_SYM_DEF_OBJECT {
                algorithm: SymmetricAlgorithm::Null.into(),
                keyBits: Default::default(),
                mode: Default::default(),
            },
        }
    }
}

impl From<SymmetricDefinitionObject> for SymmetricDefinition {
    fn from(sym_def_obj: SymmetricDefinitionObject) -> Self {
        match sym_def_obj {
            SymmetricDefinitionObject::Null => SymmetricDefinition::Null,
            SymmetricDefinitionObject::Camellia { key_bits, mode } => {
                SymmetricDefinition::Camellia { key_bits, mode }
            }
            SymmetricDefinitionObject::Aes { key_bits, mode } => {
                SymmetricDefinition::Aes { key_bits, mode }
            }
            SymmetricDefinitionObject::Sm4 { key_bits, mode } => {
                SymmetricDefinition::Sm4 { key_bits, mode }
            }
        }
    }
}

impl TryFrom<TPMT_SYM_DEF_OBJECT> for SymmetricDefinitionObject {
    type Error = Error;
    fn try_from(tpmt_sym_def_object: TPMT_SYM_DEF_OBJECT) -> Result<SymmetricDefinitionObject> {
        match SymmetricObject::try_from(tpmt_sym_def_object.algorithm)? {
            SymmetricObject::Aes => Ok(SymmetricDefinitionObject::Aes {
                key_bits: unsafe { tpmt_sym_def_object.keyBits.aes }.try_into()?,
                mode: unsafe { tpmt_sym_def_object.mode.aes }.try_into()?,
            }),
            SymmetricObject::Sm4 => Ok(SymmetricDefinitionObject::Sm4 {
                key_bits: unsafe { tpmt_sym_def_object.keyBits.sm4 }.try_into()?,
                mode: unsafe { tpmt_sym_def_object.mode.sm4 }.try_into()?,
            }),
            SymmetricObject::Camellia => Ok(SymmetricDefinitionObject::Camellia {
                key_bits: unsafe { tpmt_sym_def_object.keyBits.camellia }.try_into()?,
                mode: unsafe { tpmt_sym_def_object.mode.camellia }.try_into()?,
            }),
            SymmetricObject::Null => Ok(SymmetricDefinitionObject::Null),
            SymmetricObject::Tdes => {
                // TODO: Investigate this...
                Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm))
            }
        }
    }
}
