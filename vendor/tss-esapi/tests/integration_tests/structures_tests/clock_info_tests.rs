// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    interface_types::YesNo, structures::ClockInfo, tss2_esys::TPMS_CLOCK_INFO, Error,
    WrapperErrorKind,
};

#[test]
fn test_conversions() {
    let expected_clock = 1u64;
    let expected_reset_count = 2u32;
    let expected_restart_count = 3u32;
    let expected_safe = YesNo::Yes;

    let expected_tpms_clock_info = TPMS_CLOCK_INFO {
        clock: expected_clock,
        resetCount: expected_reset_count,
        restartCount: expected_restart_count,
        safe: expected_safe.into(),
    };

    let clock_info = ClockInfo::try_from(expected_tpms_clock_info)
        .expect("Failed to convert TPMS_CLOCK_INFO into ClockInfo");

    assert_eq!(
        expected_clock,
        clock_info.clock(),
        "'clock' value mismatch between actual and expected values"
    );
    assert_eq!(
        expected_reset_count,
        clock_info.reset_count(),
        "'reset count' value mismatch between actual and expected values"
    );
    assert_eq!(
        expected_restart_count,
        clock_info.restart_count(),
        "'restart count' value mismatch between actual and expected values"
    );
    assert_eq!(
        bool::from(expected_safe),
        clock_info.safe(),
        "'safe' value mismatch between actual and expected values"
    );

    let actual_tpms_clock_info: TPMS_CLOCK_INFO = clock_info.into();

    crate::common::ensure_tpms_clock_info_equality(
        &expected_tpms_clock_info,
        &actual_tpms_clock_info,
    );
}

#[test]
fn test_invalid_conversion() {
    assert_eq!(
        Error::WrapperError(WrapperErrorKind::InvalidParam),
        ClockInfo::try_from(TPMS_CLOCK_INFO {
            clock: 1u64,
            resetCount: 2u32,
            restartCount: 3u32,
            safe: 4u8,
        })
        .expect_err("Conversion of invalid ClockInfo parameters did not produce an error"),
        "Error produced did not match the expected error.",
    );
}
