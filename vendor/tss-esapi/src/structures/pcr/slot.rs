// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{tss2_esys::TPM2_PCR_SELECT_MAX, Error, Result, WrapperErrorKind};
use enumflags2::bitflags;
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

/// Enum with the bit flag for each PCR slot.
#[bitflags]
#[repr(u32)]
#[derive(FromPrimitive, ToPrimitive, Hash, Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
pub enum PcrSlot {
    Slot0 = 0x0000_0001,
    Slot1 = 0x0000_0002,
    Slot2 = 0x0000_0004,
    Slot3 = 0x0000_0008,
    Slot4 = 0x0000_0010,
    Slot5 = 0x0000_0020,
    Slot6 = 0x0000_0040,
    Slot7 = 0x0000_0080,
    Slot8 = 0x0000_0100,
    Slot9 = 0x0000_0200,
    Slot10 = 0x0000_0400,
    Slot11 = 0x0000_0800,
    Slot12 = 0x0000_1000,
    Slot13 = 0x0000_2000,
    Slot14 = 0x0000_4000,
    Slot15 = 0x0000_8000,
    Slot16 = 0x0001_0000,
    Slot17 = 0x0002_0000,
    Slot18 = 0x0004_0000,
    Slot19 = 0x0008_0000,
    Slot20 = 0x0010_0000,
    Slot21 = 0x0020_0000,
    Slot22 = 0x0040_0000,
    Slot23 = 0x0080_0000,
    Slot24 = 0x0100_0000,
    Slot25 = 0x0200_0000,
    Slot26 = 0x0400_0000,
    Slot27 = 0x0800_0000,
    Slot28 = 0x1000_0000,
    Slot29 = 0x2000_0000,
    Slot30 = 0x4000_0000,
    Slot31 = 0x8000_0000,
}

impl From<PcrSlot> for u32 {
    fn from(pcr_slot: PcrSlot) -> u32 {
        pcr_slot.to_u32().unwrap()
    }
}

impl TryFrom<u32> for PcrSlot {
    type Error = Error;

    fn try_from(value: u32) -> Result<PcrSlot> {
        PcrSlot::from_u32(value).ok_or_else(|| {
            error!("{} is not valid PcrSlot value", value);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

impl From<PcrSlot> for [u8; TPM2_PCR_SELECT_MAX as usize] {
    fn from(pcr_slot: PcrSlot) -> [u8; TPM2_PCR_SELECT_MAX as usize] {
        u32::from(pcr_slot).to_le_bytes()
    }
}

impl TryFrom<[u8; TPM2_PCR_SELECT_MAX as usize]> for PcrSlot {
    type Error = Error;

    fn try_from(tss_pcr_slot: [u8; TPM2_PCR_SELECT_MAX as usize]) -> Result<PcrSlot> {
        PcrSlot::try_from(u32::from_le_bytes(tss_pcr_slot))
    }
}
