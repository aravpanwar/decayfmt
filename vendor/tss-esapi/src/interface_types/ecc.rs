// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{constants::EccCurveIdentifier, tss2_esys::TPMI_ECC_CURVE, Error, Result};
use std::convert::TryFrom;
/// Enum containing the implemented ECC curves
///
/// # Details
/// This corresponds to TPMI_ECC_CURVE
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EccCurve {
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    BnP256,
    BnP638,
    Sm2P256,
}

impl From<EccCurve> for EccCurveIdentifier {
    fn from(ecc_curve: EccCurve) -> Self {
        match ecc_curve {
            EccCurve::NistP192 => EccCurveIdentifier::NistP192,
            EccCurve::NistP224 => EccCurveIdentifier::NistP224,
            EccCurve::NistP256 => EccCurveIdentifier::NistP256,
            EccCurve::NistP384 => EccCurveIdentifier::NistP384,
            EccCurve::NistP521 => EccCurveIdentifier::NistP521,
            EccCurve::BnP256 => EccCurveIdentifier::BnP256,
            EccCurve::BnP638 => EccCurveIdentifier::BnP638,
            EccCurve::Sm2P256 => EccCurveIdentifier::Sm2P256,
        }
    }
}

impl From<EccCurveIdentifier> for EccCurve {
    fn from(ecc_curve_identifier: EccCurveIdentifier) -> Self {
        match ecc_curve_identifier {
            EccCurveIdentifier::NistP192 => EccCurve::NistP192,
            EccCurveIdentifier::NistP224 => EccCurve::NistP224,
            EccCurveIdentifier::NistP256 => EccCurve::NistP256,
            EccCurveIdentifier::NistP384 => EccCurve::NistP384,
            EccCurveIdentifier::NistP521 => EccCurve::NistP521,
            EccCurveIdentifier::BnP256 => EccCurve::BnP256,
            EccCurveIdentifier::BnP638 => EccCurve::BnP638,
            EccCurveIdentifier::Sm2P256 => EccCurve::Sm2P256,
        }
    }
}

impl From<EccCurve> for TPMI_ECC_CURVE {
    fn from(curve: EccCurve) -> Self {
        EccCurveIdentifier::from(curve).into()
    }
}

impl TryFrom<TPMI_ECC_CURVE> for EccCurve {
    type Error = Error;

    fn try_from(tpmi_ecc_curve: TPMI_ECC_CURVE) -> Result<Self> {
        Ok(EccCurve::from(EccCurveIdentifier::try_from(
            tpmi_ecc_curve,
        )?))
    }
}
