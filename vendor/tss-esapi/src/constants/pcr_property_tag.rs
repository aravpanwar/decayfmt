// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::tss::{
        TPM2_PT_PCR_AUTH, TPM2_PT_PCR_DRTM_RESET, TPM2_PT_PCR_EXTEND_L0, TPM2_PT_PCR_EXTEND_L1,
        TPM2_PT_PCR_EXTEND_L2, TPM2_PT_PCR_EXTEND_L3, TPM2_PT_PCR_EXTEND_L4,
        TPM2_PT_PCR_NO_INCREMENT, TPM2_PT_PCR_POLICY, TPM2_PT_PCR_RESET_L0, TPM2_PT_PCR_RESET_L1,
        TPM2_PT_PCR_RESET_L2, TPM2_PT_PCR_RESET_L3, TPM2_PT_PCR_RESET_L4, TPM2_PT_PCR_SAVE,
    },
    tss2_esys::TPM2_PT_PCR,
    Error, Result, WrapperErrorKind,
};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

#[derive(FromPrimitive, ToPrimitive, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum PcrPropertyTag {
    Save = TPM2_PT_PCR_SAVE,
    ExtendL0 = TPM2_PT_PCR_EXTEND_L0,
    ResetL0 = TPM2_PT_PCR_RESET_L0,
    ExtendL1 = TPM2_PT_PCR_EXTEND_L1,
    ResetL1 = TPM2_PT_PCR_RESET_L1,
    ExtendL2 = TPM2_PT_PCR_EXTEND_L2,
    ResetL2 = TPM2_PT_PCR_RESET_L2,
    ExtendL3 = TPM2_PT_PCR_EXTEND_L3,
    ResetL3 = TPM2_PT_PCR_RESET_L3,
    ExtendL4 = TPM2_PT_PCR_EXTEND_L4,
    ResetL4 = TPM2_PT_PCR_RESET_L4,
    // Reserved 0x0000000B – 0x00000010
    NoIncrement = TPM2_PT_PCR_NO_INCREMENT,
    DrtmReset = TPM2_PT_PCR_DRTM_RESET,
    Policy = TPM2_PT_PCR_POLICY,
    Auth = TPM2_PT_PCR_AUTH,
}

impl From<PcrPropertyTag> for TPM2_PT_PCR {
    fn from(pcr_property_tag: PcrPropertyTag) -> Self {
        // The values are well defined so this cannot fail.
        pcr_property_tag.to_u32().unwrap()
    }
}

impl TryFrom<TPM2_PT_PCR> for PcrPropertyTag {
    type Error = Error;

    fn try_from(tpm_pt_pcr: TPM2_PT_PCR) -> Result<Self> {
        PcrPropertyTag::from_u32(tpm_pt_pcr).ok_or_else(|| {
            error!("value = {} did not match any PcrPropertyTag.", tpm_pt_pcr);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}
