// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::algorithm::PublicAlgorithm,
    structures::{
        PublicEccParameters, PublicKeyedHashParameters, PublicRsaParameters,
        SymmetricCipherParameters,
    },
    tss2_esys::{TPMT_PUBLIC_PARMS, TPMU_PUBLIC_PARMS},
    Error, Result,
};
use std::convert::{TryFrom, TryInto};
/// Enum representing the public parameters structure.
///
/// # Details
/// This corresponds to TPMT_PUBLIC_PARMS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicParameters {
    Rsa(PublicRsaParameters),
    KeyedHash(PublicKeyedHashParameters),
    Ecc(PublicEccParameters),
    SymCipher(SymmetricCipherParameters),
}

impl PublicParameters {
    /// Returns the algorithm
    pub fn algorithm(&self) -> PublicAlgorithm {
        match self {
            PublicParameters::Rsa(_) => PublicAlgorithm::Rsa,
            PublicParameters::KeyedHash(_) => PublicAlgorithm::KeyedHash,
            PublicParameters::Ecc(_) => PublicAlgorithm::Ecc,
            PublicParameters::SymCipher(_) => PublicAlgorithm::SymCipher,
        }
    }
}

impl From<PublicParameters> for TPMT_PUBLIC_PARMS {
    fn from(public_parameters: PublicParameters) -> TPMT_PUBLIC_PARMS {
        let algorithm = public_parameters.algorithm();
        match public_parameters {
            PublicParameters::Rsa(parameters) => TPMT_PUBLIC_PARMS {
                type_: algorithm.into(),
                parameters: TPMU_PUBLIC_PARMS {
                    rsaDetail: parameters.into(),
                },
            },
            PublicParameters::KeyedHash(parameters) => TPMT_PUBLIC_PARMS {
                type_: algorithm.into(),
                parameters: TPMU_PUBLIC_PARMS {
                    keyedHashDetail: parameters.into(),
                },
            },
            PublicParameters::Ecc(parameters) => TPMT_PUBLIC_PARMS {
                type_: algorithm.into(),
                parameters: TPMU_PUBLIC_PARMS {
                    eccDetail: parameters.into(),
                },
            },
            PublicParameters::SymCipher(parameters) => TPMT_PUBLIC_PARMS {
                type_: algorithm.into(),
                parameters: TPMU_PUBLIC_PARMS {
                    symDetail: parameters.into(),
                },
            },
        }
    }
}

impl TryFrom<TPMT_PUBLIC_PARMS> for PublicParameters {
    type Error = Error;

    fn try_from(tpmt_public_parms: TPMT_PUBLIC_PARMS) -> Result<Self> {
        match PublicAlgorithm::try_from(tpmt_public_parms.type_)? {
            PublicAlgorithm::Rsa => Ok(PublicParameters::Rsa(
                unsafe { tpmt_public_parms.parameters.rsaDetail }.try_into()?,
            )),
            PublicAlgorithm::KeyedHash => Ok(PublicParameters::KeyedHash(
                unsafe { tpmt_public_parms.parameters.keyedHashDetail }.try_into()?,
            )),
            PublicAlgorithm::Ecc => Ok(PublicParameters::Ecc(
                unsafe { tpmt_public_parms.parameters.eccDetail }.try_into()?,
            )),
            PublicAlgorithm::SymCipher => Ok(PublicParameters::SymCipher(
                unsafe { tpmt_public_parms.parameters.symDetail }.try_into()?,
            )),
        }
    }
}
