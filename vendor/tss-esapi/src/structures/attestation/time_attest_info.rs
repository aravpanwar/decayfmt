// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{structures::TimeInfo, tss2_esys::TPMS_TIME_ATTEST_INFO, Error, Result};
use std::convert::{TryFrom, TryInto};

/// This type is holding attested data for the command TPM2_GetTime
///
/// # Details
/// This corresponds to the TPMS_TIME_ATTEST_INFO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeAttestInfo {
    time_info: TimeInfo,
    firmware_version: u64,
}

impl TimeAttestInfo {
    /// Returns the time info
    pub const fn time_info(&self) -> &TimeInfo {
        &self.time_info
    }

    /// Returns the firmware version
    pub const fn firmware_version(&self) -> u64 {
        self.firmware_version
    }
}

impl From<TimeAttestInfo> for TPMS_TIME_ATTEST_INFO {
    fn from(time_attest_info: TimeAttestInfo) -> Self {
        TPMS_TIME_ATTEST_INFO {
            time: time_attest_info.time_info.into(),
            firmwareVersion: time_attest_info.firmware_version,
        }
    }
}

impl TryFrom<TPMS_TIME_ATTEST_INFO> for TimeAttestInfo {
    type Error = Error;

    fn try_from(tpms_time_attest_info: TPMS_TIME_ATTEST_INFO) -> Result<Self> {
        Ok(TimeAttestInfo {
            time_info: tpms_time_attest_info.time.try_into()?,
            firmware_version: tpms_time_attest_info.firmwareVersion,
        })
    }
}
