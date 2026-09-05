use crate::{Error, Result, WrapperErrorKind};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{From, TryFrom};

use crate::{
    constants::tss::{
        TPM2_CAP_ACT, TPM2_CAP_ALGS, TPM2_CAP_AUDIT_COMMANDS, TPM2_CAP_AUTH_POLICIES,
        TPM2_CAP_COMMANDS, TPM2_CAP_ECC_CURVES, TPM2_CAP_HANDLES, TPM2_CAP_PCRS,
        TPM2_CAP_PCR_PROPERTIES, TPM2_CAP_PP_COMMANDS, TPM2_CAP_TPM_PROPERTIES,
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
    PpCommands = TPM2_CAP_PP_COMMANDS,
    AuditCommands = TPM2_CAP_AUDIT_COMMANDS,
    AssignedPcr = TPM2_CAP_PCRS,
    TpmProperties = TPM2_CAP_TPM_PROPERTIES,
    PcrProperties = TPM2_CAP_PCR_PROPERTIES,
    EccCurves = TPM2_CAP_ECC_CURVES,
    AuthPolicies = TPM2_CAP_AUTH_POLICIES,
    Act = TPM2_CAP_ACT,
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
