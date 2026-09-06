// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        tss::{
            TPM2_PT_PCR_AUTH, TPM2_PT_PCR_DRTM_RESET, TPM2_PT_PCR_EXTEND_L0, TPM2_PT_PCR_EXTEND_L1,
            TPM2_PT_PCR_EXTEND_L2, TPM2_PT_PCR_EXTEND_L3, TPM2_PT_PCR_EXTEND_L4,
            TPM2_PT_PCR_NO_INCREMENT, TPM2_PT_PCR_POLICY, TPM2_PT_PCR_RESET_L0,
            TPM2_PT_PCR_RESET_L1, TPM2_PT_PCR_RESET_L2, TPM2_PT_PCR_RESET_L3, TPM2_PT_PCR_RESET_L4,
            TPM2_PT_PCR_SAVE,
        },
        PcrPropertyTag,
    },
    tss2_esys::TPM2_PT_PCR,
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tpm_pt_pcrs:ident, PcrPropertyTag::$item:ident) => {
        assert_eq!(
            $tpm_pt_pcrs,
            TPM2_PT_PCR::from(PcrPropertyTag::$item),
            "Failed to convert {} to TPM2_PT_PCR",
            std::stringify!(PcrPropertyTag::$item),
        );

        assert_eq!(
            PcrPropertyTag::$item,
            PcrPropertyTag::try_from($tpm_pt_pcrs).expect(&format!(
                "Failed to convert {} to a PcrPropertyTag",
                std::stringify!($tpm_pt_pcrs)
            )),
            "{} did not convert into {}",
            std::stringify!($tpm_pt_pcrs),
            std::stringify!(PcrPropertyTag::$item),
        )
    };
}

#[test]
fn test_invalid_conversions() {
    const INVALID_PT_PCR_VALUE: TPM2_PT_PCR = 0xFFFFFFFF;
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        PcrPropertyTag::try_from(INVALID_PT_PCR_VALUE),
        "Expected an error when converting 0xFFFFFFFF to a PcrPropertyTag"
    );
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TPM2_PT_PCR_SAVE, PcrPropertyTag::Save);
    test_valid_conversion!(TPM2_PT_PCR_RESET_L0, PcrPropertyTag::ResetL0);
    test_valid_conversion!(TPM2_PT_PCR_EXTEND_L0, PcrPropertyTag::ExtendL0);
    test_valid_conversion!(TPM2_PT_PCR_RESET_L1, PcrPropertyTag::ResetL1);
    test_valid_conversion!(TPM2_PT_PCR_EXTEND_L1, PcrPropertyTag::ExtendL1);
    test_valid_conversion!(TPM2_PT_PCR_RESET_L2, PcrPropertyTag::ResetL2);
    test_valid_conversion!(TPM2_PT_PCR_EXTEND_L2, PcrPropertyTag::ExtendL2);
    test_valid_conversion!(TPM2_PT_PCR_RESET_L3, PcrPropertyTag::ResetL3);
    test_valid_conversion!(TPM2_PT_PCR_EXTEND_L3, PcrPropertyTag::ExtendL3);
    test_valid_conversion!(TPM2_PT_PCR_RESET_L4, PcrPropertyTag::ResetL4);
    test_valid_conversion!(TPM2_PT_PCR_EXTEND_L4, PcrPropertyTag::ExtendL4);
    test_valid_conversion!(TPM2_PT_PCR_NO_INCREMENT, PcrPropertyTag::NoIncrement);
    test_valid_conversion!(TPM2_PT_PCR_DRTM_RESET, PcrPropertyTag::DrtmReset);
    test_valid_conversion!(TPM2_PT_PCR_POLICY, PcrPropertyTag::Policy);
    test_valid_conversion!(TPM2_PT_PCR_AUTH, PcrPropertyTag::Auth);
}
