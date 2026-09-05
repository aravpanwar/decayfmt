// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::algorithm::SignatureSchemeAlgorithm,
    structures::{EccSignature, HashAgile, RsaSignature},
    traits::{Marshall, UnMarshall},
    tss2_esys::{TPMT_SIGNATURE, TPMU_SIGNATURE},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
};
use tss_esapi_sys::{Tss2_MU_TPMT_SIGNATURE_Marshal, Tss2_MU_TPMT_SIGNATURE_Unmarshal};

/// Enum representing a Signature
///
/// # Details
/// This corresponds TPMT_SIGNATURE
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    RsaSsa(RsaSignature),
    RsaPss(RsaSignature),
    EcDsa(EccSignature),
    EcDaa(EccSignature),
    Sm2(EccSignature),
    EcSchnorr(EccSignature),
    Hmac(HashAgile),
    Null,
}

impl Signature {
    pub fn algorithm(&self) -> SignatureSchemeAlgorithm {
        match self {
            Signature::RsaSsa(_) => SignatureSchemeAlgorithm::RsaSsa,
            Signature::RsaPss(_) => SignatureSchemeAlgorithm::RsaPss,
            Signature::EcDsa(_) => SignatureSchemeAlgorithm::EcDsa,
            Signature::EcDaa(_) => SignatureSchemeAlgorithm::EcDaa,
            Signature::Sm2(_) => SignatureSchemeAlgorithm::Sm2,
            Signature::EcSchnorr(_) => SignatureSchemeAlgorithm::EcSchnorr,
            Signature::Hmac(_) => SignatureSchemeAlgorithm::Hmac,
            Signature::Null => SignatureSchemeAlgorithm::Null,
        }
    }
}

impl TryFrom<Signature> for TPMT_SIGNATURE {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<Self> {
        let signature_algorithm = signature.algorithm().into();
        match signature {
            Signature::RsaSsa(rsa_signature) => Ok(TPMT_SIGNATURE {
                sigAlg: signature_algorithm,
                signature: TPMU_SIGNATURE {
                    rsassa: rsa_signature.into(),
                },
            }),
            Signature::RsaPss(rsa_signature) => Ok(TPMT_SIGNATURE {
                sigAlg: signature_algorithm,
                signature: TPMU_SIGNATURE {
                    rsapss: rsa_signature.into(),
                },
            }),
            Signature::EcDsa(ecc_signature) => Ok(TPMT_SIGNATURE {
                sigAlg: signature_algorithm,
                signature: TPMU_SIGNATURE {
                    ecdsa: ecc_signature.into(),
                },
            }),
            Signature::EcDaa(ecc_signature) => Ok(TPMT_SIGNATURE {
                sigAlg: signature_algorithm,
                signature: TPMU_SIGNATURE {
                    ecdaa: ecc_signature.into(),
                },
            }),
            Signature::Sm2(ecc_signature) => Ok(TPMT_SIGNATURE {
                sigAlg: signature_algorithm,
                signature: TPMU_SIGNATURE {
                    sm2: ecc_signature.into(),
                },
            }),
            Signature::EcSchnorr(ecc_signature) => Ok(TPMT_SIGNATURE {
                sigAlg: signature_algorithm,
                signature: TPMU_SIGNATURE {
                    ecschnorr: ecc_signature.into(),
                },
            }),
            Signature::Hmac(hash_agile) => Ok(TPMT_SIGNATURE {
                sigAlg: signature_algorithm,
                signature: TPMU_SIGNATURE {
                    hmac: hash_agile.try_into()?,
                },
            }),
            Signature::Null => Ok(TPMT_SIGNATURE {
                sigAlg: signature_algorithm,
                signature: Default::default(),
            }),
        }
    }
}

impl TryFrom<TPMT_SIGNATURE> for Signature {
    type Error = Error;

    fn try_from(tpmt_signature: TPMT_SIGNATURE) -> Result<Self> {
        match SignatureSchemeAlgorithm::try_from(tpmt_signature.sigAlg)? {
            SignatureSchemeAlgorithm::RsaSsa => Ok(Signature::RsaSsa(
                unsafe { tpmt_signature.signature.rsassa }.try_into()?,
            )),
            SignatureSchemeAlgorithm::RsaPss => Ok(Signature::RsaPss(
                unsafe { tpmt_signature.signature.rsapss }.try_into()?,
            )),
            SignatureSchemeAlgorithm::EcDsa => Ok(Signature::EcDsa(
                unsafe { tpmt_signature.signature.ecdsa }.try_into()?,
            )),
            SignatureSchemeAlgorithm::EcDaa => Ok(Signature::EcDaa(
                unsafe { tpmt_signature.signature.ecdaa }.try_into()?,
            )),
            SignatureSchemeAlgorithm::Sm2 => Ok(Signature::Sm2(
                unsafe { tpmt_signature.signature.sm2 }.try_into()?,
            )),
            SignatureSchemeAlgorithm::EcSchnorr => Ok(Signature::EcSchnorr(
                unsafe { tpmt_signature.signature.ecschnorr }.try_into()?,
            )),
            SignatureSchemeAlgorithm::Hmac => Ok(Signature::Hmac(
                unsafe { tpmt_signature.signature.hmac }.try_into()?,
            )),
            SignatureSchemeAlgorithm::Null => Ok(Signature::Null),
        }
    }
}

impl Marshall for Signature {
    #[allow(unused_qualifications)]
    const BUFFER_SIZE: usize = size_of::<TPMT_SIGNATURE>();

    /// Produce a marshalled [`TPMT_SIGNATURE`]
    fn marshall(&self) -> Result<Vec<u8>> {
        let tpmt_sig = TPMT_SIGNATURE::try_from(self.clone())?;
        let mut offset = 0;
        let mut buffer = vec![0; Self::BUFFER_SIZE];

        let ret = unsafe {
            Tss2_MU_TPMT_SIGNATURE_Marshal(
                &tpmt_sig,
                buffer.as_mut_ptr(),
                buffer.capacity().try_into().map_err(|e| {
                    error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?,
                &mut offset,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let checked_offset = usize::try_from(offset).map_err(|e| {
                error!("Failed to parse offset as usize: {}", e);
                Error::local_error(WrapperErrorKind::InvalidParam)
            })?;

            buffer.truncate(checked_offset);
            Ok(buffer)
        } else {
            Err(ret)
        }
    }
}

impl UnMarshall for Signature {
    /// Unmarshall the structure from [`TPMT_SIGNATURE`]
    fn unmarshall(public_buffer: &[u8]) -> Result<Self> {
        let mut tpmt_sig = TPMT_SIGNATURE::default();
        let mut offset = 0;

        let ret = unsafe {
            Tss2_MU_TPMT_SIGNATURE_Unmarshal(
                public_buffer.as_ptr(),
                public_buffer.len().try_into().map_err(|e| {
                    error!("Failed to convert length of marshalled data: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?,
                &mut offset,
                &mut tpmt_sig,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(tpmt_sig.try_into()?)
        } else {
            Err(ret)
        }
    }
}
