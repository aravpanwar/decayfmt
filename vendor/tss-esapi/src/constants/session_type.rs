// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{TPM2_SE_HMAC, TPM2_SE_POLICY, TPM2_SE_TRIAL},
    tss2_esys::TPM2_SE,
    Error, Result, WrapperErrorKind,
};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

/// Enum representing the different TPM session types.
#[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionType {
    Hmac = TPM2_SE_HMAC,
    Policy = TPM2_SE_POLICY,
    Trial = TPM2_SE_TRIAL,
}

impl From<SessionType> for TPM2_SE {
    fn from(session_type: SessionType) -> TPM2_SE {
        // The values are well defined so this cannot fail.
        session_type.to_u8().unwrap()
    }
}

impl TryFrom<TPM2_SE> for SessionType {
    type Error = Error;
    fn try_from(tpm_session_type: TPM2_SE) -> Result<SessionType> {
        SessionType::from_u8(tpm_session_type).ok_or_else(|| {
            error!(
                "value = {} did not match any SessionType.",
                tpm_session_type
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}
