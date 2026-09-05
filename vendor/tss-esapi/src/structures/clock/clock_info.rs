// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{interface_types::YesNo, tss2_esys::TPMS_CLOCK_INFO, Error, Result};
use std::convert::TryFrom;

/// Information related to the internal temporal
/// state of the TPM.
///
/// # Details
/// Corresponds to `TPMS_CLOCK_INFO`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockInfo {
    clock: u64,
    reset_count: u32,
    restart_count: u32,
    safe: YesNo,
}

impl ClockInfo {
    /// Returns the clock value
    pub const fn clock(&self) -> u64 {
        self.clock
    }

    /// Returns the reset count value
    pub const fn reset_count(&self) -> u32 {
        self.reset_count
    }

    /// Returns the restart count value
    pub const fn restart_count(&self) -> u32 {
        self.restart_count
    }

    /// Returns safe
    pub fn safe(&self) -> bool {
        self.safe.into()
    }
}

impl TryFrom<TPMS_CLOCK_INFO> for ClockInfo {
    type Error = Error;

    fn try_from(tss: TPMS_CLOCK_INFO) -> Result<Self> {
        Ok(ClockInfo {
            clock: tss.clock,
            reset_count: tss.resetCount,
            restart_count: tss.restartCount,
            safe: YesNo::try_from(tss.safe)?,
        })
    }
}

impl From<ClockInfo> for TPMS_CLOCK_INFO {
    fn from(native: ClockInfo) -> Self {
        TPMS_CLOCK_INFO {
            clock: native.clock,
            resetCount: native.reset_count,
            restartCount: native.restart_count,
            safe: native.safe.into(),
        }
    }
}
