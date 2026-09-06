// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    interface_types::YesNo,
    structures::{ClockInfo, TimeInfo},
    tss2_esys::{TPMS_CLOCK_INFO, TPMS_TIME_INFO},
};

use std::convert::TryFrom;

#[test]
fn test_conversion() {
    let expected_time = 1u64;
    let expected_clock_info = ClockInfo::try_from(TPMS_CLOCK_INFO {
        clock: 1u64,
        resetCount: 2u32,
        restartCount: 3u32,
        safe: YesNo::Yes.into(),
    })
    .expect("Failed to create ClockInfo");
    let expected_tpms_time_info = TPMS_TIME_INFO {
        time: expected_time,
        clockInfo: expected_clock_info.into(),
    };

    let time_info = TimeInfo::try_from(expected_tpms_time_info)
        .expect("Failed to convert TPMS_TIME_INFO into TimeInfo");

    assert_eq!(
        expected_time,
        time_info.time(),
        "The TimeInfo that was converted from TPMS_TIME_INFO, did not contain the expected value for time",
    );
    assert_eq!(
        &expected_clock_info,
        time_info.clock_info(),
        "The TimeInfo that was converted from TPMS_TIME_INFO, did not contain the expected value for 'clock info'",
    );

    let actual_tpms_time_info = time_info.into();
    crate::common::ensure_tpms_time_info_equality(&expected_tpms_time_info, &actual_tpms_time_info);
}
