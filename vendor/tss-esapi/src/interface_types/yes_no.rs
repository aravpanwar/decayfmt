// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{tss2_esys::TPMI_YES_NO, Error, Result, WrapperErrorKind};
use std::convert::TryFrom;

/// Enum representing a yes or no.
///
/// # Details
/// This corresponds to the TPMI_YES_NO interface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YesNo {
    Yes,
    No,
}

impl From<bool> for YesNo {
    fn from(value: bool) -> Self {
        if value {
            YesNo::Yes
        } else {
            YesNo::No
        }
    }
}

impl From<YesNo> for bool {
    fn from(yes_no: YesNo) -> Self {
        match yes_no {
            YesNo::Yes => true,
            YesNo::No => false,
        }
    }
}

impl From<YesNo> for TPMI_YES_NO {
    fn from(yes_no: YesNo) -> Self {
        match yes_no {
            YesNo::Yes => 1,
            YesNo::No => 0,
        }
    }
}

impl TryFrom<TPMI_YES_NO> for YesNo {
    type Error = Error;

    fn try_from(tpmi_yes_no: TPMI_YES_NO) -> Result<Self> {
        match tpmi_yes_no {
            0 => Ok(YesNo::No),
            1 => Ok(YesNo::Yes),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
