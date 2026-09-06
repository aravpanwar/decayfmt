// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{tss2_esys::TPM2_PCR_SELECT_MAX, Error, Result, WrapperErrorKind};

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

use log::error;
use std::convert::TryFrom;

/// Enum with the possible values for sizeofSelect.
#[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum PcrSelectSize {
    OneOctet = 1,
    TwoOctets = 2,
    ThreeOctets = 3,
    FourOctets = 4,
}

impl PcrSelectSize {
    /// Returns the PcrSelectSize value as u8
    pub fn as_u8(&self) -> u8 {
        // The value is well defined so unwrap will
        // never cause panic.
        self.to_u8().unwrap()
    }

    /// Returns the PcrSelectSize value as u32
    pub fn as_u32(&self) -> u32 {
        // The value is well defined so unwrap will
        // never cause panic.
        self.to_u32().unwrap()
    }

    /// Returns the PcrSelectSize value as usize
    pub fn as_usize(&self) -> usize {
        // The value is well defined so unwrap will
        // never cause panic.
        self.to_usize().unwrap()
    }

    /// Parses the u8 value as PcrSelectSize
    pub fn try_parse_u8(value: u8) -> Result<Self> {
        PcrSelectSize::from_u8(value).ok_or_else(|| {
            error!(
                "Error converting sizeofSelect to a SelectSize: Invalid value {}",
                value
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }

    /// Parses the u32 value as PcrSelectSize
    pub fn try_parse_u32(value: u32) -> Result<Self> {
        PcrSelectSize::from_u32(value).ok_or_else(|| {
            error!(
                "Error converting sizeofSelect to a SelectSize: Invalid value {}",
                value
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }

    /// Parses the usize value as PcrSelectSize
    pub fn try_parse_usize(value: usize) -> Result<Self> {
        PcrSelectSize::from_usize(value).ok_or_else(|| {
            error!(
                "Error converting sizeofSelect to a SelectSize: Invalid value {}",
                value
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

/// The default for PcrSelectSize is three octets.
/// A value for the sizeofSelect that works
/// on most platforms.
impl Default for PcrSelectSize {
    fn default() -> PcrSelectSize {
        match TPM2_PCR_SELECT_MAX {
            1 => PcrSelectSize::OneOctet,
            2 => PcrSelectSize::TwoOctets,
            _ => PcrSelectSize::ThreeOctets,
        }
    }
}

impl TryFrom<u8> for PcrSelectSize {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        if u32::from(value) > TPM2_PCR_SELECT_MAX {
            error!(
                "Found size of select value(= {}) that is larger then TPM2_PCR_SELECT_MAX(={}",
                value, TPM2_PCR_SELECT_MAX
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        PcrSelectSize::try_parse_u8(value)
    }
}

impl TryFrom<PcrSelectSize> for u8 {
    type Error = Error;

    fn try_from(pcr_select_size: PcrSelectSize) -> Result<Self> {
        if pcr_select_size.as_u32() > TPM2_PCR_SELECT_MAX {
            error!("The number of octets specified by PcrSelectSize value us greater then TPM2_PCR_SELECT_MAX");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(pcr_select_size.as_u8())
    }
}
