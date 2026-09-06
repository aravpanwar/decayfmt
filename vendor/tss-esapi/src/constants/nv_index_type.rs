// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{
        TPM2_NT_BITS, TPM2_NT_COUNTER, TPM2_NT_EXTEND, TPM2_NT_ORDINARY, TPM2_NT_PIN_FAIL,
        TPM2_NT_PIN_PASS,
    },
    tss2_esys::TPM2_NT,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::TryFrom;

/// Enum with values representing the NV index type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NvIndexType {
    Ordinary,
    Counter,
    Bits,
    Extend,
    PinFail,
    PinPass,
}

impl From<NvIndexType> for TPM2_NT {
    fn from(nv_index_type: NvIndexType) -> TPM2_NT {
        match nv_index_type {
            NvIndexType::Ordinary => TPM2_NT_ORDINARY,
            NvIndexType::Counter => TPM2_NT_COUNTER,
            NvIndexType::Bits => TPM2_NT_BITS,
            NvIndexType::Extend => TPM2_NT_EXTEND,
            NvIndexType::PinFail => TPM2_NT_PIN_FAIL,
            NvIndexType::PinPass => TPM2_NT_PIN_PASS,
        }
    }
}

impl TryFrom<TPM2_NT> for NvIndexType {
    type Error = Error;
    fn try_from(tss_nv_index_type: TPM2_NT) -> Result<NvIndexType> {
        match tss_nv_index_type {
            TPM2_NT_ORDINARY => Ok(NvIndexType::Ordinary),
            TPM2_NT_COUNTER => Ok(NvIndexType::Counter),
            TPM2_NT_BITS => Ok(NvIndexType::Bits),
            TPM2_NT_EXTEND => Ok(NvIndexType::Extend),
            TPM2_NT_PIN_FAIL => Ok(NvIndexType::PinFail),
            TPM2_NT_PIN_PASS => Ok(NvIndexType::PinPass),
            _ => {
                error!("Found invalid value when trying to parse Nv Index Type");
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}
