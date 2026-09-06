// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{
        TPM2_ECC_BN_P256, TPM2_ECC_BN_P638, TPM2_ECC_NIST_P192, TPM2_ECC_NIST_P224,
        TPM2_ECC_NIST_P256, TPM2_ECC_NIST_P384, TPM2_ECC_NIST_P521, TPM2_ECC_SM2_P256,
    },
    tss2_esys::TPM2_ECC_CURVE,
    Error, Result, WrapperErrorKind,
};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;
/// Enum that contains the constants for the
/// implemented elliptic curves.
///
/// # Details
/// This corresponds to `TPM2_ECC_CURVE`
#[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EccCurveIdentifier {
    NistP192 = TPM2_ECC_NIST_P192,
    NistP224 = TPM2_ECC_NIST_P224,
    NistP256 = TPM2_ECC_NIST_P256,
    NistP384 = TPM2_ECC_NIST_P384,
    NistP521 = TPM2_ECC_NIST_P521,
    BnP256 = TPM2_ECC_BN_P256,
    BnP638 = TPM2_ECC_BN_P638,
    Sm2P256 = TPM2_ECC_SM2_P256,
}

impl From<EccCurveIdentifier> for TPM2_ECC_CURVE {
    fn from(curve: EccCurveIdentifier) -> Self {
        // The values are well defined so this cannot fail.
        curve.to_u16().unwrap()
    }
}

impl TryFrom<TPM2_ECC_CURVE> for EccCurveIdentifier {
    type Error = Error;

    fn try_from(tpm2_ecc_curve: TPM2_ECC_CURVE) -> Result<Self> {
        EccCurveIdentifier::from_u16(tpm2_ecc_curve).ok_or_else(|| {
            error!("Value = {} did not match any ecc curve.", tpm2_ecc_curve);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}
