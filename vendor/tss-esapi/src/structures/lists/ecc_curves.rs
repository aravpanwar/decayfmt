// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::constants::ecc::EccCurveIdentifier;
use crate::tss2_esys::{TPM2_ECC_CURVE, TPML_ECC_CURVE};
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::TryFrom;
use std::ops::Deref;

/// A list of ECC curves
///
/// # Details
/// This corresponds to `TPML_ECC_CURVE`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EccCurveList {
    ecc_curves: Vec<EccCurveIdentifier>,
}

impl EccCurveList {
    pub const MAX_SIZE: usize = Self::calculate_max_size();

    pub fn new() -> Self {
        EccCurveList {
            ecc_curves: Vec::new(),
        }
    }

    /// Adds an ECC curve to the list of curves.
    pub fn add(&mut self, ecc_curve: EccCurveIdentifier) -> Result<()> {
        if self.ecc_curves.len() + 1 > EccCurveList::MAX_SIZE {
            error!(
                "Adding ECC curve to list will make the list exceeded its maximum count(> {})",
                EccCurveList::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        self.ecc_curves.push(ecc_curve);
        Ok(())
    }

    /// Returns the inner type.
    pub fn into_inner(self) -> Vec<EccCurveIdentifier> {
        self.ecc_curves
    }

    /// Private function that calculates the maximum number
    /// elements allowed in internal storage.
    const fn calculate_max_size() -> usize {
        crate::structures::capability_data::max_cap_size::<TPM2_ECC_CURVE>()
    }
}

impl TryFrom<TPML_ECC_CURVE> for EccCurveList {
    type Error = Error;

    fn try_from(ecc_curves: TPML_ECC_CURVE) -> Result<Self> {
        let ecc_curve_count = ecc_curves.count as usize;
        if ecc_curve_count > Self::MAX_SIZE {
            error!("Error: Invalid TPML_ECC_CURVE count(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        ecc_curves.eccCurves[..ecc_curve_count]
            .iter()
            .map(|&cc| EccCurveIdentifier::try_from(cc))
            .collect::<Result<Vec<EccCurveIdentifier>>>()
            .map(|ecc_curves| EccCurveList { ecc_curves })
    }
}

impl From<EccCurveList> for TPML_ECC_CURVE {
    fn from(ecc_curves: EccCurveList) -> Self {
        let mut tss_ecc_curves: TPML_ECC_CURVE = Default::default();
        for ecc_curve in ecc_curves.ecc_curves {
            tss_ecc_curves.eccCurves[tss_ecc_curves.count as usize] = ecc_curve.into();
            tss_ecc_curves.count += 1;
        }
        tss_ecc_curves
    }
}

impl TryFrom<Vec<EccCurveIdentifier>> for EccCurveList {
    type Error = Error;

    fn try_from(ecc_curves: Vec<EccCurveIdentifier>) -> Result<Self> {
        if ecc_curves.len() > Self::MAX_SIZE {
            error!("Error: Invalid TPML_ECC_CURVE count(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(EccCurveList { ecc_curves })
    }
}

impl From<EccCurveList> for Vec<EccCurveIdentifier> {
    fn from(ecc_curve_list: EccCurveList) -> Self {
        ecc_curve_list.ecc_curves
    }
}

impl AsRef<[EccCurveIdentifier]> for EccCurveList {
    fn as_ref(&self) -> &[EccCurveIdentifier] {
        self.ecc_curves.as_slice()
    }
}

impl Deref for EccCurveList {
    type Target = Vec<EccCurveIdentifier>;

    fn deref(&self) -> &Self::Target {
        &self.ecc_curves
    }
}
