// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    constants::{
        tss::{
            TPM2_NT_BITS, TPM2_NT_COUNTER, TPM2_NT_EXTEND, TPM2_NT_ORDINARY, TPM2_NT_PIN_FAIL,
            TPM2_NT_PIN_PASS,
        },
        NvIndexType,
    },
    tss2_esys::TPM2_NT,
};

use std::convert::{From, TryFrom};

#[test]
fn test_conversion_to_tss_type() {
    assert_eq!(TPM2_NT_ORDINARY, TPM2_NT::from(NvIndexType::Ordinary));
    assert_eq!(TPM2_NT_COUNTER, TPM2_NT::from(NvIndexType::Counter));
    assert_eq!(TPM2_NT_BITS, TPM2_NT::from(NvIndexType::Bits));
    assert_eq!(TPM2_NT_EXTEND, TPM2_NT::from(NvIndexType::Extend));
    assert_eq!(TPM2_NT_PIN_FAIL, TPM2_NT::from(NvIndexType::PinFail));
    assert_eq!(TPM2_NT_PIN_PASS, TPM2_NT::from(NvIndexType::PinPass));
}

#[test]
fn test_conversion_from_tss_type() {
    assert_eq!(
        NvIndexType::Ordinary,
        NvIndexType::try_from(TPM2_NT_ORDINARY).unwrap()
    );
    assert_eq!(
        NvIndexType::Counter,
        NvIndexType::try_from(TPM2_NT_COUNTER).unwrap()
    );
    assert_eq!(
        NvIndexType::Bits,
        NvIndexType::try_from(TPM2_NT_BITS).unwrap()
    );
    assert_eq!(
        NvIndexType::Extend,
        NvIndexType::try_from(TPM2_NT_EXTEND).unwrap()
    );
    assert_eq!(
        NvIndexType::PinFail,
        NvIndexType::try_from(TPM2_NT_PIN_FAIL).unwrap()
    );
    assert_eq!(
        NvIndexType::PinPass,
        NvIndexType::try_from(TPM2_NT_PIN_PASS).unwrap()
    );

    const INVALID_VALUE: TPM2_NT = 15;
    let _ = NvIndexType::try_from(INVALID_VALUE).unwrap_err();
}
