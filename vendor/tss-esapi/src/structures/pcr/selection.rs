// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{PcrSelectSize, PcrSlot, PcrSlotCollection},
    tss2_esys::TPMS_PCR_SELECTION,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::TryFrom;
/// This module contains the PcrSelection struct.
/// The TSS counterpart of this struct is the
/// TPMS_PCR_SELECTION.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PcrSelection {
    hashing_algorithm: HashingAlgorithm,
    pcr_slot_collection: PcrSlotCollection,
}

impl PcrSelection {
    /// Creates new PcrSelection
    ///
    /// # Errors
    /// Returns InconsistentParams error if a pcr slot
    /// has been provided that ends up in an octet outside the
    /// range specified by the `size_of_select` parameter.
    pub fn create(
        hashing_algorithm: HashingAlgorithm,
        size_of_select: PcrSelectSize,
        selected_pcr_slots: &[PcrSlot],
    ) -> Result<Self> {
        PcrSlotCollection::create(size_of_select, selected_pcr_slots).map(|pcr_slot_collection| {
            PcrSelection {
                hashing_algorithm,
                pcr_slot_collection,
            }
        })
    }

    /// Returns the hashing algorithm for the selection
    pub const fn hashing_algorithm(&self) -> HashingAlgorithm {
        self.hashing_algorithm
    }

    /// Returns 'Size of Select'
    ///
    /// NB! This is not the same as how many [PcrSlot]
    /// there are in the selection but rather how many
    /// octets that are needed to hold the bit field
    /// that indicate what slots that are selected.
    pub const fn size_of_select(&self) -> PcrSelectSize {
        self.pcr_slot_collection.size_of_select()
    }

    /// Returns the selected pcrs.
    pub fn selected(&self) -> Vec<PcrSlot> {
        self.pcr_slot_collection.collection()
    }

    /// Returns true if the specified [PcrSlot] is selected in
    /// the [PcrSelection].
    pub fn is_selected(&self, pcr_slot: PcrSlot) -> bool {
        self.pcr_slot_collection.contains(pcr_slot)
    }

    /// Removes the specified [PcrSlot]s from the selected pcrs.
    ///
    /// # Errors
    /// If one of the specified pcr slots does not exist in the selected pcrs.
    pub fn deselect_exact(&mut self, pcr_slot: PcrSlot) -> Result<()> {
        self.pcr_slot_collection.remove_exact(pcr_slot)
    }

    /// Removes the specified [PcrSlot]s from the selected pcrs.
    pub fn deselect(&mut self, pcr_slot: PcrSlot) {
        self.pcr_slot_collection.remove(pcr_slot)
    }

    /// Merges another [PcrSelection] into `self` if the
    /// elements in the collection does not already exist
    /// in `self`.
    ///
    /// # Constraints
    /// * Cannot be called with `other` that has a hashing_algorithm
    ///   that is different from the one in `self`.
    /// * Cannot be called with `other` that has a size_of_select
    ///   that is different from the one in `self`.
    /// * Cannot be called with `other`that contains pcr slots present
    ///   in `self`.
    ///
    /// # Errors
    /// Returns InvalidParam if there is a hashing algorithm mismatch
    /// Returns InvalidParam if there is size of select mismatch.
    /// Returns InvalidParam if `other` contains items that are present in `self`
    pub fn merge_exact(&mut self, other: &Self) -> Result<()> {
        // Check that the hashing algorithm match
        if self.hashing_algorithm != other.hashing_algorithm {
            error!("Found inconsistencies in the hashing algorithm");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        self.pcr_slot_collection
            .merge_exact(&other.pcr_slot_collection)
    }

    /// Removes the selected pcr slots in `other` from `self`if none
    /// of the pcr slots are present in `self`.
    ///
    /// # Constraints
    /// * Cannot be called with `other` that has a hashing_algorithm
    ///   that is different from the one in `self`.
    /// * Cannot be called with `other` that has a size_of_select
    ///   that is different from the one in `self`.
    /// * Cannot be called with `other`that contains pcr slots not present
    ///   in `self`.
    pub fn subtract_exact(&mut self, other: &Self) -> Result<()> {
        // Check that the hashing algorithm match
        if self.hashing_algorithm != other.hashing_algorithm {
            error!("Mismatched hashing algorithm ");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        self.pcr_slot_collection
            .subtract_exact(&other.pcr_slot_collection)
    }

    /// Indicates whether the pcr selection is empty.
    pub fn is_empty(&self) -> bool {
        self.pcr_slot_collection.is_empty()
    }
}

impl TryFrom<TPMS_PCR_SELECTION> for PcrSelection {
    type Error = Error;

    fn try_from(tss_pcr_selection: TPMS_PCR_SELECTION) -> Result<Self> {
        // Parse hashing algorithm.
        let hashing_algorithm =
            HashingAlgorithm::try_from(tss_pcr_selection.hash).map_err(|e| {
                error!("Error converting hash to a HashingAlgorithm: {}", e);
                Error::local_error(WrapperErrorKind::InvalidParam)
            })?;

        let pcr_slot_collection = PcrSlotCollection::try_from((
            tss_pcr_selection.sizeofSelect,
            tss_pcr_selection.pcrSelect,
        ))?;

        Ok(PcrSelection {
            hashing_algorithm,
            pcr_slot_collection,
        })
    }
}

impl From<PcrSelection> for TPMS_PCR_SELECTION {
    fn from(pcr_selection: PcrSelection) -> Self {
        let (size_of_select, pcr_select) = pcr_selection.pcr_slot_collection.into();
        TPMS_PCR_SELECTION {
            hash: pcr_selection.hashing_algorithm.into(),
            sizeofSelect: size_of_select,
            pcrSelect: pcr_select,
        }
    }
}
