// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{TPM2_SU_CLEAR, TPM2_SU_STATE},
    tss2_esys::TPM2_SU,
    Error, Result, WrapperErrorKind,
};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;
/// Enum repsenting the different TPM Startup Type values.
#[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum StartupType {
    Clear = TPM2_SU_CLEAR,
    State = TPM2_SU_STATE,
}

impl From<StartupType> for TPM2_SU {
    fn from(startup_type: StartupType) -> TPM2_SU {
        // The values are well defined so this cannot fail.
        startup_type.to_u16().unwrap()
    }
}

impl TryFrom<TPM2_SU> for StartupType {
    type Error = Error;
    fn try_from(tpm_startup_type: TPM2_SU) -> Result<StartupType> {
        StartupType::from_u16(tpm_startup_type).ok_or_else(|| {
            error!(
                "value = {} did not match any StartupType.",
                tpm_startup_type
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}
