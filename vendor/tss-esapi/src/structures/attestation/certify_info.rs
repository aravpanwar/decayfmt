// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{structures::Name, tss2_esys::TPMS_CERTIFY_INFO, Error, Result};
use std::convert::{TryFrom, TryInto};
/// This a struct holding the attested data for the command TPM2_Certify
///
/// # Details
/// This corresponds to the TPMS_CERTIFY_INFO.
#[derive(Debug, Clone)]
pub struct CertifyInfo {
    name: Name,
    qualified_name: Name,
}

impl CertifyInfo {
    /// Returns a reference to the name
    pub const fn name(&self) -> &Name {
        &self.name
    }

    /// Returns a reference to the qualified name
    pub const fn qualified_name(&self) -> &Name {
        &self.qualified_name
    }
}

impl From<CertifyInfo> for TPMS_CERTIFY_INFO {
    fn from(certify_info: CertifyInfo) -> Self {
        TPMS_CERTIFY_INFO {
            name: certify_info.name.into(),
            qualifiedName: certify_info.qualified_name.into(),
        }
    }
}

impl TryFrom<TPMS_CERTIFY_INFO> for CertifyInfo {
    type Error = Error;

    fn try_from(tpms_certify_info: TPMS_CERTIFY_INFO) -> Result<Self> {
        Ok(CertifyInfo {
            name: tpms_certify_info.name.try_into()?,
            qualified_name: tpms_certify_info.qualifiedName.try_into()?,
        })
    }
}
