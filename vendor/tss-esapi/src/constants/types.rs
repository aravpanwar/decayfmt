// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{From, TryFrom};

pub mod capability {
    use super::*;
    use crate::{
        constants::tss::{
            TPM2_CAP_ALGS, TPM2_CAP_AUDIT_COMMANDS, TPM2_CAP_COMMANDS, TPM2_CAP_ECC_CURVES,
            TPM2_CAP_HANDLES, TPM2_CAP_PCRS, TPM2_CAP_PCR_PROPERTIES, TPM2_CAP_PP_COMMANDS,
            TPM2_CAP_TPM_PROPERTIES,
        },
        tss2_esys::TPM2_CAP,
    };

    // Enum representing the different TPM Capability Type values.
    #[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
    #[repr(u32)]
    pub enum CapabilityType {
        Algorithms = TPM2_CAP_ALGS,
        Handles = TPM2_CAP_HANDLES,
        Command = TPM2_CAP_COMMANDS,
        PPCommands = TPM2_CAP_PP_COMMANDS,
        AuditCommands = TPM2_CAP_AUDIT_COMMANDS,
        AssignedPCR = TPM2_CAP_PCRS,
        TPMProperties = TPM2_CAP_TPM_PROPERTIES,
        PCRProperties = TPM2_CAP_PCR_PROPERTIES,
        ECCCurves = TPM2_CAP_ECC_CURVES,
    }

    impl From<CapabilityType> for TPM2_CAP {
        fn from(capability_type: CapabilityType) -> TPM2_CAP {
            // The values are well defined so this cannot fail.
            capability_type.to_u32().unwrap()
        }
    }

    impl TryFrom<TPM2_CAP> for CapabilityType {
        type Error = Error;
        fn try_from(tpm_capability_type: TPM2_CAP) -> Result<CapabilityType> {
            CapabilityType::from_u32(tpm_capability_type).ok_or_else(|| {
                error!(
                    "value = {} did not match any CapabilityType.",
                    tpm_capability_type
                );
                Error::local_error(WrapperErrorKind::InvalidParam)
            })
        }
    }
}

/// Startup module
pub mod startup {
    use super::*;
    use crate::{
        constants::tss::{TPM2_SU_CLEAR, TPM2_SU_STATE},
        tss2_esys::TPM2_SU,
    };

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
}

/// Session module
pub mod session {
    use super::*;
    use crate::{
        constants::tss::{TPM2_SE_HMAC, TPM2_SE_POLICY, TPM2_SE_TRIAL},
        tss2_esys::TPM2_SE,
    };

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
}
