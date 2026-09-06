// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::algorithm::PublicAlgorithm,
    structures::{Auth, Digest, EccParameter, PrivateKeyRsa, SensitiveData, SymmetricKey},
    traits::{Marshall, UnMarshall},
    tss2_esys::{TPM2B_SENSITIVE, TPMT_SENSITIVE, TPMU_SENSITIVE_COMPOSITE},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
};

/// Enum describing the Sensitive part of an object.
///
/// # Details
/// This corresponds to TPMT_SENSITIVE
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Sensitive {
    Rsa {
        auth_value: Auth,
        seed_value: Digest,
        sensitive: PrivateKeyRsa,
    },
    Ecc {
        auth_value: Auth,
        seed_value: Digest,
        sensitive: EccParameter,
    },
    Bits {
        auth_value: Auth,
        seed_value: Digest,
        sensitive: SensitiveData,
    },
    Symmetric {
        auth_value: Auth,
        seed_value: Digest,
        sensitive: SymmetricKey,
    },
    // Even though this is included in TPMU_SENSITIVE_COMPOSITE, there is no
    // selector for it, so it can't be converted back and forth
    // VendorSpecific {
    //     auth_value: Auth,
    //     seed_value: Digest,
    //     sensitive: PrivateVendorSpecific,
    // },
}

impl Sensitive {
    /// Get the authentication value of the object
    pub fn auth_value(&self) -> &Auth {
        match self {
            Sensitive::Rsa { auth_value, .. }
            | Sensitive::Ecc { auth_value, .. }
            | Sensitive::Bits { auth_value, .. }
            | Sensitive::Symmetric { auth_value, .. } => auth_value,
        }
    }

    /// Get the seed value of the object
    pub fn seed_value(&self) -> &Digest {
        match self {
            Sensitive::Rsa { seed_value, .. }
            | Sensitive::Ecc { seed_value, .. }
            | Sensitive::Bits { seed_value, .. }
            | Sensitive::Symmetric { seed_value, .. } => seed_value,
        }
    }

    pub fn sensitive_type(&self) -> PublicAlgorithm {
        match self {
            Sensitive::Rsa { .. } => PublicAlgorithm::Rsa,
            Sensitive::Ecc { .. } => PublicAlgorithm::Ecc,
            Sensitive::Bits { .. } => PublicAlgorithm::KeyedHash,
            Sensitive::Symmetric { .. } => PublicAlgorithm::SymCipher,
        }
    }
}

impl From<Sensitive> for TPMT_SENSITIVE {
    fn from(sensitive: Sensitive) -> Self {
        #[allow(non_snake_case)]
        let sensitiveType = sensitive.sensitive_type().into();
        match sensitive {
            Sensitive::Rsa {
                auth_value,
                seed_value,
                sensitive,
            } => TPMT_SENSITIVE {
                sensitiveType,
                authValue: auth_value.into(),
                seedValue: seed_value.into(),
                sensitive: TPMU_SENSITIVE_COMPOSITE {
                    rsa: sensitive.into(),
                },
            },
            Sensitive::Ecc {
                auth_value,
                seed_value,
                sensitive,
            } => TPMT_SENSITIVE {
                sensitiveType,
                authValue: auth_value.into(),
                seedValue: seed_value.into(),
                sensitive: TPMU_SENSITIVE_COMPOSITE {
                    ecc: sensitive.into(),
                },
            },
            Sensitive::Bits {
                auth_value,
                seed_value,
                sensitive,
            } => TPMT_SENSITIVE {
                sensitiveType,
                authValue: auth_value.into(),
                seedValue: seed_value.into(),
                sensitive: TPMU_SENSITIVE_COMPOSITE {
                    bits: sensitive.into(),
                },
            },
            Sensitive::Symmetric {
                auth_value,
                seed_value,
                sensitive,
            } => TPMT_SENSITIVE {
                sensitiveType,
                authValue: auth_value.into(),
                seedValue: seed_value.into(),
                sensitive: TPMU_SENSITIVE_COMPOSITE {
                    sym: sensitive.into(),
                },
            },
        }
    }
}

impl TryFrom<TPMT_SENSITIVE> for Sensitive {
    type Error = Error;

    fn try_from(tpmt_sensitive: TPMT_SENSITIVE) -> Result<Sensitive> {
        let sensitive_type = PublicAlgorithm::try_from(tpmt_sensitive.sensitiveType)?;
        match sensitive_type {
            PublicAlgorithm::Rsa => Ok(Sensitive::Rsa {
                auth_value: tpmt_sensitive.authValue.try_into()?,
                seed_value: tpmt_sensitive.seedValue.try_into()?,
                sensitive: unsafe { tpmt_sensitive.sensitive.rsa }.try_into()?,
            }),
            PublicAlgorithm::Ecc => Ok(Sensitive::Ecc {
                auth_value: tpmt_sensitive.authValue.try_into()?,
                seed_value: tpmt_sensitive.seedValue.try_into()?,
                sensitive: unsafe { tpmt_sensitive.sensitive.ecc }.try_into()?,
            }),
            PublicAlgorithm::KeyedHash => Ok(Sensitive::Bits {
                auth_value: tpmt_sensitive.authValue.try_into()?,
                seed_value: tpmt_sensitive.seedValue.try_into()?,
                sensitive: unsafe { tpmt_sensitive.sensitive.bits }.try_into()?,
            }),
            PublicAlgorithm::SymCipher => Ok(Sensitive::Symmetric {
                auth_value: tpmt_sensitive.authValue.try_into()?,
                seed_value: tpmt_sensitive.seedValue.try_into()?,
                sensitive: unsafe { tpmt_sensitive.sensitive.sym }.try_into()?,
            }),
        }
    }
}

impl Marshall for Sensitive {
    const BUFFER_SIZE: usize = size_of::<TPMT_SENSITIVE>();

    /// Produce a marshalled [`TPMT_SENSITIVE`]
    ///
    /// Note: for [TPM2B_SENSITIVE] marshalling use [SensitiveBuffer][`crate::structures::SensitiveBuffer]
    fn marshall(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; Self::BUFFER_SIZE];
        let mut offset = 0;

        let ret = Error::from_tss_rc(unsafe {
            crate::tss2_esys::Tss2_MU_TPMT_SENSITIVE_Marshal(
                &self.clone().into(),
                buffer.as_mut_ptr(),
                Self::BUFFER_SIZE.try_into().map_err(|e| {
                    error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?,
                &mut offset,
            )
        });

        if !ret.is_success() {
            return Err(ret);
        }

        let checked_offset = usize::try_from(offset).map_err(|e| {
            error!("Failed to parse offset as usize: {}", e);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        buffer.truncate(checked_offset);

        Ok(buffer)
    }
}

impl UnMarshall for Sensitive {
    /// Unmarshall the structure from [`TPMT_SENSITIVE`]
    ///
    /// Note: for [TPM2B_SENSITIVE] marshalling use [SensitiveBuffer][`crate::structures::SensitiveBuffer]
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self> {
        let mut dest = TPMT_SENSITIVE::default();
        let mut offset = 0;

        let ret = Error::from_tss_rc(unsafe {
            crate::tss2_esys::Tss2_MU_TPMT_SENSITIVE_Unmarshal(
                marshalled_data.as_ptr(),
                marshalled_data.len().try_into().map_err(|e| {
                    error!("Failed to convert length of marshalled data: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?,
                &mut offset,
                &mut dest,
            )
        });

        if !ret.is_success() {
            return Err(ret);
        }

        Sensitive::try_from(dest)
    }
}

impl TryFrom<TPM2B_SENSITIVE> for Sensitive {
    type Error = Error;

    fn try_from(tpm2b_sensitive: TPM2B_SENSITIVE) -> Result<Self> {
        Sensitive::try_from(tpm2b_sensitive.sensitiveArea)
    }
}

impl TryFrom<Sensitive> for TPM2B_SENSITIVE {
    type Error = Error;

    fn try_from(sensitive: Sensitive) -> Result<Self> {
        let mut buffer = vec![0; Sensitive::BUFFER_SIZE];
        let mut size = 0;
        let sensitive_area = TPMT_SENSITIVE::from(sensitive);

        let ret = Error::from_tss_rc(unsafe {
            crate::tss2_esys::Tss2_MU_TPMT_SENSITIVE_Marshal(
                &sensitive_area,
                buffer.as_mut_ptr(),
                Sensitive::BUFFER_SIZE.try_into().map_err(|e| {
                    error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?,
                &mut size,
            )
        });

        if !ret.is_success() {
            return Err(ret);
        }

        Ok(TPM2B_SENSITIVE {
            size: size.try_into().map_err(|e| {
                error!(
                    "Failed to convert size of buffer from TSS size_t type: {}",
                    e
                );
                Error::local_error(WrapperErrorKind::InvalidParam)
            })?,
            sensitiveArea: sensitive_area,
        })
    }
}
