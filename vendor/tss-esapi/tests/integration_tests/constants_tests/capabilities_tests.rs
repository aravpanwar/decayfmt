// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        tss::{
            TPM2_CAP_ACT, TPM2_CAP_ALGS, TPM2_CAP_AUDIT_COMMANDS, TPM2_CAP_AUTH_POLICIES,
            TPM2_CAP_COMMANDS, TPM2_CAP_ECC_CURVES, TPM2_CAP_HANDLES, TPM2_CAP_PCRS,
            TPM2_CAP_PCR_PROPERTIES, TPM2_CAP_PP_COMMANDS, TPM2_CAP_TPM_PROPERTIES,
        },
        CapabilityType,
    },
    tss2_esys::TPM2_CAP,
    Error, WrapperErrorKind,
};

#[test]
fn test_invalid_conversions() {
    const INVALID_CAPABILTY_TYPE_VALUE: TPM2_CAP = 0xFFFFFFFF;
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        CapabilityType::try_from(INVALID_CAPABILTY_TYPE_VALUE),
        "Expected an error when converting 0xFFFFFFFF to a CapabilityType"
    );
}

macro_rules! test_valid_conversion {
    ($tpm_capabilities:ident, CapabilityType::$capabilities:ident) => {
        assert_eq!(
            $tpm_capabilities,
            TPM2_CAP::from(CapabilityType::$capabilities),
            "Failed to convert {} to TPM2_CAP",
            std::stringify!(CapabilityType::$capabilities),
        );

        assert_eq!(
            CapabilityType::$capabilities,
            CapabilityType::try_from($tpm_capabilities).expect(&format!(
                "Failed to convert {} to a CapabilityType",
                std::stringify!($tpm_capabilities)
            )),
            "{} did not convert into {}",
            std::stringify!($tpm_capabilities),
            std::stringify!(CapabilityType::$capabilities),
        )
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TPM2_CAP_ALGS, CapabilityType::Algorithms);
    test_valid_conversion!(TPM2_CAP_HANDLES, CapabilityType::Handles);
    test_valid_conversion!(TPM2_CAP_COMMANDS, CapabilityType::Command);
    test_valid_conversion!(TPM2_CAP_PP_COMMANDS, CapabilityType::PpCommands);
    test_valid_conversion!(TPM2_CAP_AUDIT_COMMANDS, CapabilityType::AuditCommands);
    test_valid_conversion!(TPM2_CAP_PCRS, CapabilityType::AssignedPcr);
    test_valid_conversion!(TPM2_CAP_TPM_PROPERTIES, CapabilityType::TpmProperties);
    test_valid_conversion!(TPM2_CAP_PCR_PROPERTIES, CapabilityType::PcrProperties);
    test_valid_conversion!(TPM2_CAP_ECC_CURVES, CapabilityType::EccCurves);
    test_valid_conversion!(TPM2_CAP_AUTH_POLICIES, CapabilityType::AuthPolicies);
    test_valid_conversion!(TPM2_CAP_ACT, CapabilityType::Act);
}
