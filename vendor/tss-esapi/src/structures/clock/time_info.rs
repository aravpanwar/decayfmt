// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{structures::ClockInfo, tss2_esys::TPMS_TIME_INFO, Error, Result};
use std::convert::{TryFrom, TryInto};

/// Structure holding the attestation for
/// TPM2_GetTime() and TPM2_ReadClock().
///
/// # Details
/// This corresponds to the TPMS_TIME_INFO
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeInfo {
    time: u64,
    clock_info: ClockInfo,
}

impl TimeInfo {
    /// Returns the time
    pub const fn time(&self) -> u64 {
        self.time
    }

    /// Restursn the clock info.
    pub const fn clock_info(&self) -> &ClockInfo {
        &self.clock_info
    }
}

impl From<TimeInfo> for TPMS_TIME_INFO {
    fn from(time_info: TimeInfo) -> Self {
        TPMS_TIME_INFO {
            time: time_info.time,
            clockInfo: time_info.clock_info.into(),
        }
    }
}

impl TryFrom<TPMS_TIME_INFO> for TimeInfo {
    type Error = Error;

    fn try_from(tpms_time_info: TPMS_TIME_INFO) -> Result<Self> {
        Ok(TimeInfo {
            time: tpms_time_info.time,
            clock_info: tpms_time_info.clockInfo.try_into()?,
        })
    }
}
