// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{interface_types::YesNo, tss2_esys::TPMI_YES_NO, Error, WrapperErrorKind};
#[test]
fn test_conversions() {
    let expected_yes_value: TPMI_YES_NO = 1;
    let expected_no_value: TPMI_YES_NO = 0;

    assert_eq!(
        expected_yes_value,
        TPMI_YES_NO::from(YesNo::Yes),
        "Yes did not convert to the correct value '{}'",
        expected_yes_value,
    );
    assert_eq!(
        expected_no_value,
        TPMI_YES_NO::from(YesNo::No),
        "No did not convert to the correct value '{}'",
        expected_no_value,
    );
    assert_eq!(
        YesNo::Yes,
        YesNo::try_from(1).expect("Failed to convert interface type to enum for Yes"),
        "'1' did not convert to the correct value Yes"
    );
    assert_eq!(
        YesNo::No,
        YesNo::try_from(0).expect("Failed to convert interface type to enum for No"),
        "'0' did not convert to the correct value No"
    );
    assert!(
        bool::from(YesNo::Yes),
        "Yes did not convert to the correct boolean value 'true'"
    );
    assert!(
        !bool::from(YesNo::No),
        "No did not convert to the correct boolean value 'false'"
    );
}

#[test]
fn test_invalid_conversions() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        YesNo::try_from(100),
        "Conversion of invalid value did not result in expected result"
    );
}
