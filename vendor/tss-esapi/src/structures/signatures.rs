// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{EccParameter, PublicKeyRsa},
    tss2_esys::{TPMS_SIGNATURE_ECC, TPMS_SIGNATURE_RSA},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};

/// Type holding RSA signature information.
///
/// For more information about the contents of `signature` see Annex B
/// in the Architecture spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaSignature {
    hashing_algorithm: HashingAlgorithm,
    signature: PublicKeyRsa,
}

impl RsaSignature {
    /// Creates new RSA signature
    ///
    /// # Errors
    /// Using [Null][`HashingAlgorithm::Null`] will cause an error.
    pub fn create(hashing_algorithm: HashingAlgorithm, signature: PublicKeyRsa) -> Result<Self> {
        if hashing_algorithm == HashingAlgorithm::Null {
            error!("Hashing algorithm Null is not allowed in RsaSignature");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(RsaSignature {
            hashing_algorithm,
            signature,
        })
    }

    /// Returns the hashing algorithm
    pub const fn hashing_algorithm(&self) -> HashingAlgorithm {
        self.hashing_algorithm
    }

    /// Returns the signature
    pub const fn signature(&self) -> &PublicKeyRsa {
        &self.signature
    }
}

impl From<RsaSignature> for TPMS_SIGNATURE_RSA {
    fn from(rsa_signature: RsaSignature) -> Self {
        TPMS_SIGNATURE_RSA {
            hash: rsa_signature.hashing_algorithm.into(),
            sig: rsa_signature.signature.into(),
        }
    }
}

impl TryFrom<TPMS_SIGNATURE_RSA> for RsaSignature {
    type Error = Error;

    fn try_from(tpms_signature_rsa: TPMS_SIGNATURE_RSA) -> Result<Self> {
        let hashing_algorithm = tpms_signature_rsa.hash.try_into()?;
        if hashing_algorithm == HashingAlgorithm::Null {
            error!("Received invalid hashing algorithm Null from the tpm in the RSA signature.");
            return Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm));
        }

        Ok(RsaSignature {
            hashing_algorithm,
            signature: tpms_signature_rsa.sig.try_into()?,
        })
    }
}

/// Type holding ECC signature information.
///
/// For more information about the contents of `signature_r` and `signature_s`
/// see Annex B in the Architecture spec (or Annex D for SM2 signatures).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccSignature {
    hashing_algorithm: HashingAlgorithm,
    signature_r: EccParameter,
    signature_s: EccParameter,
}

impl EccSignature {
    /// Creates new ECC signature
    pub fn create(
        hashing_algorithm: HashingAlgorithm,
        signature_r: EccParameter,
        signature_s: EccParameter,
    ) -> Result<Self> {
        if hashing_algorithm == HashingAlgorithm::Null {
            error!("Hashing algorithm Null is not allowed in RsaSignature");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(EccSignature {
            hashing_algorithm,
            signature_r,
            signature_s,
        })
    }

    /// Returns the hashing algorithm
    pub const fn hashing_algorithm(&self) -> HashingAlgorithm {
        self.hashing_algorithm
    }

    /// Returns signature r
    pub const fn signature_r(&self) -> &EccParameter {
        &self.signature_r
    }

    /// Returns signature s
    pub const fn signature_s(&self) -> &EccParameter {
        &self.signature_s
    }
}

impl From<EccSignature> for TPMS_SIGNATURE_ECC {
    fn from(ecc_signature: EccSignature) -> Self {
        TPMS_SIGNATURE_ECC {
            hash: ecc_signature.hashing_algorithm.into(),
            signatureR: ecc_signature.signature_r.into(),
            signatureS: ecc_signature.signature_s.into(),
        }
    }
}

impl TryFrom<TPMS_SIGNATURE_ECC> for EccSignature {
    type Error = Error;

    fn try_from(tpms_signature_ecc: TPMS_SIGNATURE_ECC) -> Result<Self> {
        let hashing_algorithm = tpms_signature_ecc.hash.try_into()?;
        if hashing_algorithm == HashingAlgorithm::Null {
            error!("Received invalid hashing algorithm Null from the tpm in the ECC signature.");
            return Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm));
        }
        Ok(EccSignature {
            hashing_algorithm,
            signature_r: tpms_signature_ecc.signatureR.try_into()?,
            signature_s: tpms_signature_ecc.signatureS.try_into()?,
        })
    }
}
