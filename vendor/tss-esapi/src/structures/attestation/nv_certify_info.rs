// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::{MaxNvBuffer, Name},
    tss2_esys::TPMS_NV_CERTIFY_INFO,
    Error, Result,
};
use std::convert::{TryFrom, TryInto};
/// This  structure  contains  the  Name  and  contents  of  the
/// selected  NV  Index  that  is  certified  by TPM2_NV_Certify()
///
/// # Details
/// This corresponds to the TPMS_NV_CERTIFY_INFO.
#[derive(Debug, Clone)]
pub struct NvCertifyInfo {
    index_name: Name,
    offset: u16,
    nv_contents: MaxNvBuffer,
}

impl NvCertifyInfo {
    /// Returns index name
    pub const fn index_name(&self) -> &Name {
        &self.index_name
    }

    /// Returns offset
    pub const fn offset(&self) -> u16 {
        self.offset
    }

    /// Returns nv contents
    pub const fn nv_contents(&self) -> &MaxNvBuffer {
        &self.nv_contents
    }
}

impl From<NvCertifyInfo> for TPMS_NV_CERTIFY_INFO {
    fn from(nv_certify_info: NvCertifyInfo) -> Self {
        TPMS_NV_CERTIFY_INFO {
            indexName: nv_certify_info.index_name.into(),
            offset: nv_certify_info.offset,
            nvContents: nv_certify_info.nv_contents.into(),
        }
    }
}

impl TryFrom<TPMS_NV_CERTIFY_INFO> for NvCertifyInfo {
    type Error = Error;

    fn try_from(tpms_nv_certify_info: TPMS_NV_CERTIFY_INFO) -> Result<Self> {
        Ok(NvCertifyInfo {
            index_name: tpms_nv_certify_info.indexName.try_into()?,
            offset: tpms_nv_certify_info.offset,
            nv_contents: tpms_nv_certify_info.nvContents.try_into()?,
        })
    }
}
