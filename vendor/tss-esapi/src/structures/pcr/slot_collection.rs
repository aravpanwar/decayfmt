// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::{PcrSelectSize, PcrSlot},
    tss2_esys::TPM2_PCR_SELECT_MAX,
    Error, Result, WrapperErrorKind,
};
use enumflags2::BitFlags;
use log::error;
use std::convert::TryFrom;

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct PcrSlotCollection {
    pcr_select_size: PcrSelectSize,
    pcr_slots: BitFlags<PcrSlot>,
}

impl PcrSlotCollection {
    const MAX_SIZE: usize = TPM2_PCR_SELECT_MAX as usize;

    /// Creates a new PcrSlotCollection
    pub fn new() -> Self {
        PcrSlotCollection::default()
    }

    /// Creates a PcrCollection from the given arguments.
    pub fn create(pcr_select_size: PcrSelectSize, pcr_slots: &[PcrSlot]) -> Result<Self> {
        Self::validate_parameters(pcr_select_size, pcr_slots)?;

        Ok(PcrSlotCollection {
            pcr_select_size,
            pcr_slots: pcr_slots.iter().copied().collect(),
        })
    }

    /// Validates that the combination of parameters
    /// provided can be used together.
    pub fn validate_parameters(
        pcr_select_size: PcrSelectSize,
        pcr_slots: &[PcrSlot],
    ) -> Result<()> {
        let _number_of_octets: u32 = u8::try_from(pcr_select_size).map(u32::from)?;

        let max_pcr_slot_value = Self::calculate_max_pcr_slots_value(pcr_select_size);

        if pcr_slots
            .iter()
            .any(|&item| u32::from(item) > max_pcr_slot_value)
        {
            error!("pcr_slots contained a pcr slot that does not reside in octets specified by size_of_select");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }
        Ok(())
    }

    /// Returns the size of the select.
    pub const fn size_of_select(&self) -> PcrSelectSize {
        self.pcr_select_size
    }

    /// Returns true if the collection contains the
    /// specified pcr slot.
    pub fn contains(&self, pcr_slot: PcrSlot) -> bool {
        self.pcr_slots.contains(pcr_slot)
    }

    /// Returns true if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.pcr_slots.is_empty()
    }

    /// Returns the pcr slots in the collection.
    pub fn collection(&self) -> Vec<PcrSlot> {
        self.pcr_slots.iter().collect()
    }

    /// Removes pcr slot from the collection
    pub fn remove(&mut self, pcr_slot: PcrSlot) {
        self.pcr_slots.remove(pcr_slot)
    }

    /// Removes pcr slot from the collection if it
    /// exists.
    ///
    /// # Constraints
    /// Cannot remove a pcr slot from the collection
    /// if it does not reside inside the collection.
    ///
    /// # Errors
    /// Returns InvalidParam error if the collection
    /// did not contain the specified pcr slot.
    pub fn remove_exact(&mut self, pcr_slot: PcrSlot) -> Result<()> {
        self.ensure_contains_all(pcr_slot, "remove_exact")?;
        self.pcr_slots.remove(pcr_slot);
        Ok(())
    }

    /// Merges another PcrSlotCollection into `self` if it contains no
    /// pcr slots that are already present in `self`.
    ///
    /// # Errors
    /// Returns InconsistentParams if a size of select mismatch is detected.
    /// Returns InvalidParam if `other` contains items that are present in `self`
    pub fn merge_exact(&mut self, other: &Self) -> Result<()> {
        // Check that size of select match.
        self.ensure_pcr_select_size_equality(other, "merge_exact")?;
        self.ensure_contains_none(other.pcr_slots, "merge_exact")?;
        self.pcr_slots |= other.pcr_slots;
        Ok(())
    }

    /// Subtracts another PcrSlotCollection from `self` if none the
    /// items in the other collection is present in `self`.
    ///
    /// # Errors
    /// Returns InconsistentParams if a size of select mismatch is detected.
    /// Returns InvalidParam if `other` contains items that are not present in `self`
    pub fn subtract_exact(&mut self, other: &Self) -> Result<()> {
        // Check that size of select match.
        self.ensure_pcr_select_size_equality(other, "subtract_unique")?;
        self.ensure_contains_all(other.pcr_slots, "subtract_unique")?;
        self.pcr_slots.remove(other.pcr_slots);
        Ok(())
    }

    /// Private method for ensuring that a size of select
    /// is equal to the one present in `self`.
    fn ensure_pcr_select_size_equality(
        &self,
        other: &PcrSlotCollection,
        action: &str,
    ) -> Result<()> {
        if self.pcr_select_size != other.pcr_select_size {
            error!(
                "Failed to perform '{}' due to size of select mismatch",
                action
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(())
    }

    /// Private method for ensuring that provided pcr slots does not
    /// already exists in `self`.
    fn ensure_contains_none(&self, pcr_slots: BitFlags<PcrSlot>, action: &str) -> Result<()> {
        if self.pcr_slots.intersects(pcr_slots) {
            error!(
                "Failed to perform '{}' because `self` contained the specified pcr slots",
                action
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(())
    }

    /// Private method that ensures that all the specified pcr slots
    /// exists in `self`.
    fn ensure_contains_all<T>(&self, pcr_slots: T, action: &str) -> Result<()>
    where
        T: Into<BitFlags<PcrSlot>>,
    {
        if self.pcr_slots.contains(pcr_slots) {
            Ok(())
        } else {
            error!(
                "Failed to perform '{}' because `self` did not contain the specified pcr slots",
                action
            );
            Err(Error::local_error(WrapperErrorKind::InvalidParam))
        }
    }

    /// Private function for parsing the octets into the internal representation.
    fn parse_octets(
        mut octets: [u8; PcrSlotCollection::MAX_SIZE],
        pcr_select_size: PcrSelectSize,
    ) -> Result<BitFlags<PcrSlot>> {
        // Mask all octets not indicated by pcr_select_size
        // to be included.
        octets[..]
            .iter_mut()
            .enumerate()
            .for_each(|(index, value)| {
                if index + 1 > pcr_select_size.as_usize() {
                    *value = 0u8;
                }
            });

        BitFlags::<PcrSlot>::try_from(u32::from_le_bytes(octets)).map_err(|e| {
            error!("Error parsing octets to a BitFlags<PcrSlot>: {}", e);
            Error::local_error(WrapperErrorKind::UnsupportedParam)
        })
    }

    /// Private function that calculates the maximum value for
    /// pcr slots with regard to the PcrSelectSize
    const fn calculate_max_pcr_slots_value(pcr_select_size: PcrSelectSize) -> u32 {
        match pcr_select_size {
            PcrSelectSize::OneOctet => 0x000000FF,
            PcrSelectSize::TwoOctets => 0x0000FFFF,
            PcrSelectSize::ThreeOctets => 0x00FFFFFF,
            PcrSelectSize::FourOctets => 0xFFFFFFFF,
        }
    }
}

impl From<PcrSlotCollection> for (u8, [u8; PcrSlotCollection::MAX_SIZE]) {
    fn from(pcr_slot_collection: PcrSlotCollection) -> Self {
        // PcrSlotCollection should not be able to contain
        // an invalid pcr_select_size.
        let size_of_select = pcr_slot_collection.pcr_select_size.as_u8();
        let number_of_octets = pcr_slot_collection.pcr_select_size.as_usize();
        let u32_bytes = pcr_slot_collection.pcr_slots.bits().to_le_bytes();
        let mut octets: [u8; TPM2_PCR_SELECT_MAX as usize] = Default::default();
        octets[..number_of_octets].copy_from_slice(&u32_bytes[..number_of_octets]);
        (size_of_select, octets)
    }
}

impl TryFrom<(u8, [u8; Self::MAX_SIZE])> for PcrSlotCollection {
    type Error = Error;

    fn try_from((size_of_select, octets): (u8, [u8; Self::MAX_SIZE])) -> Result<Self> {
        let pcr_select_size = PcrSelectSize::try_from(size_of_select)?;
        Ok(PcrSlotCollection {
            pcr_select_size,
            pcr_slots: PcrSlotCollection::parse_octets(octets, pcr_select_size)?,
        })
    }
}
