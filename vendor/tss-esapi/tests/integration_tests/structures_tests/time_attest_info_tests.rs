// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    interface_types::YesNo,
    structures::{TimeAttestInfo, TimeInfo},
    tss2_esys::{TPMS_CLOCK_INFO, TPMS_TIME_ATTEST_INFO, TPMS_TIME_INFO},
};

#[test]
fn test_conversion() {
    let expected_time_info = TimeInfo::try_from(TPMS_TIME_INFO {
        time: 12u64,
        clockInfo: TPMS_CLOCK_INFO {
            clock: 1u64,
            resetCount: 2u32,
            restartCount: 3u32,
            safe: YesNo::Yes.into(),
        },
    })
    .expect("Failed to convert TPMS_TIME_INFO into TimeInfo");
    let expected_firmware_version = 0xfffffu64;
    let expected_tpms_time_attest_info = TPMS_TIME_ATTEST_INFO {
        time: expected_time_info.into(),
        firmwareVersion: expected_firmware_version,
    };

    let time_attest_info = TimeAttestInfo::try_from(expected_tpms_time_attest_info)
        .expect("Unable to convert TPMS_TIME_ATTEST_INFO into TimeAttestInfo");

    assert_eq!(
        &expected_time_info,
        time_attest_info.time_info(),
        "The TimeAttestInfo that was converted from TPMS_TIME_ATTEST_INFO, did not contain the expected value for 'time info'",
    );
    assert_eq!(
        expected_firmware_version,
        time_attest_info.firmware_version(),
        "The TimeAttestInfo that was converted from TPMS_TIME_ATTEST_INFO, did not contain the expected value for 'firmware version'",
    );

    let actual_tpms_time_attest_info: TPMS_TIME_ATTEST_INFO = time_attest_info.into();

    crate::common::ensure_tpms_time_attest_info_equality(
        &expected_tpms_time_attest_info,
        &actual_tpms_time_attest_info,
    );
}
