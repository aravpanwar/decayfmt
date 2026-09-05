// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::interface_types::algorithm::HashingAlgorithm;
use crate::structures::{PcrSelectSize, PcrSelection, PcrSlot};
use crate::tss2_esys::TPML_PCR_SELECTION;
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::collections::HashMap;
use std::convert::TryFrom;

/// A struct representing a pcr selection list. This
/// corresponds to the TSS TPML_PCR_SELECTION.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PcrSelectionList {
    items: Vec<PcrSelection>,
}

impl PcrSelectionList {
    pub const MAX_SIZE: usize = 16;
    /// Function for retrieiving the number of banks in the selection
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true if the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Gets the selections
    pub fn get_selections(&self) -> &[PcrSelection] {
        &self.items
    }

    /// Subtracts other from self
    pub fn subtract(&mut self, other: &Self) -> Result<()> {
        if self == other {
            self.items.clear();
            return Ok(());
        }

        if self.is_empty() {
            error!("Cannot remove items that does not exist");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        for other_pcr_selection in other.get_selections() {
            self.remove_selection(other_pcr_selection)?;
        }

        self.remove_empty_selections();
        Ok(())
    }

    /// Function for retrieving the PcrSelectionList from `Option<PcrSelectionList>`
    ///
    /// This returns an empty list if None is passed
    pub fn list_from_option(pcr_list: Option<PcrSelectionList>) -> PcrSelectionList {
        pcr_list.unwrap_or_default()
    }

    /// Private methods for removing pcr selections that are empty.
    fn remove_empty_selections(&mut self) {
        self.items.retain(|v| !v.is_empty());
    }

    /// Private method for removing the items defined in a [PcrSelection]
    /// from the data in the [PcrSelectionList].
    fn remove_selection(&mut self, pcr_selection: &PcrSelection) -> Result<()> {
        pcr_selection.selected().iter().try_for_each(|&pcr_slot| {
            self.items
                .iter_mut()
                .find(|existing_pcr_selection| {
                    existing_pcr_selection.hashing_algorithm() == pcr_selection.hashing_algorithm()
                        && existing_pcr_selection.is_selected(pcr_slot)
                })
                .ok_or_else(|| {
                    error!("Cannot remove items from a selection that does not exists");
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })
                .and_then(|existing_pcr_selection| existing_pcr_selection.deselect_exact(pcr_slot))
        })
    }

    /// Get a builder for this structure
    pub fn builder() -> PcrSelectionListBuilder {
        PcrSelectionListBuilder::new()
    }
}

impl From<PcrSelectionList> for TPML_PCR_SELECTION {
    fn from(pcr_selections: PcrSelectionList) -> Self {
        let mut tss_pcr_selection_list: TPML_PCR_SELECTION = Default::default();
        for pcr_selection in pcr_selections.items {
            tss_pcr_selection_list.pcrSelections[tss_pcr_selection_list.count as usize] =
                pcr_selection.into();
            tss_pcr_selection_list.count += 1;
        }
        tss_pcr_selection_list
    }
}

impl TryFrom<TPML_PCR_SELECTION> for PcrSelectionList {
    type Error = Error;
    fn try_from(tpml_pcr_selection: TPML_PCR_SELECTION) -> Result<PcrSelectionList> {
        let size = tpml_pcr_selection.count as usize;

        if size > PcrSelectionList::MAX_SIZE {
            error!(
                "Invalid size value in TPML_PCR_SELECTION (> {})",
                PcrSelectionList::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        let mut items = Vec::<PcrSelection>::with_capacity(size);
        // Loop over available selections
        for tpms_pcr_selection in tpml_pcr_selection.pcrSelections[..size].iter() {
            // Parse pcr selection.
            let parsed_pcr_selection = PcrSelection::try_from(*tpms_pcr_selection)?;
            items.push(parsed_pcr_selection);
        }
        Ok(PcrSelectionList { items })
    }
}

/// A builder for the PcrSelectionList struct.
#[derive(Debug, Default)]
pub struct PcrSelectionListBuilder {
    size_of_select: Option<PcrSelectSize>,
    items: HashMap<HashingAlgorithm, Vec<PcrSlot>>,
}

impl PcrSelectionListBuilder {
    pub fn new() -> Self {
        PcrSelectionListBuilder {
            size_of_select: None,
            items: Default::default(),
        }
    }

    /// Set the size of the pcr selection(sizeofSelect)
    ///
    /// # Arguments
    /// size_of_select -- The size that will be used for all selections(sizeofSelect).
    pub fn with_size_of_select(mut self, size_of_select: PcrSelectSize) -> Self {
        self.size_of_select = Some(size_of_select);
        self
    }

    /// Adds a selection associated with a specific HashingAlgorithm.
    ///
    /// This function will not overwrite the values already associated
    /// with a specific HashingAlgorithm only update.
    ///
    /// # Arguments
    /// hash_algorithm -- The HashingAlgorithm associated with the pcr selection
    /// pcr_slots      -- The PCR slots in the selection.
    pub fn with_selection(
        mut self,
        hash_algorithm: HashingAlgorithm,
        pcr_slots: &[PcrSlot],
    ) -> Self {
        // let selected_pcr_slots: BitFlags<PcrSlot> = pcr_slots.iter().cloned().collect();
        match self.items.get_mut(&hash_algorithm) {
            Some(previously_selected_pcr_slots) => {
                // *previously_selected_pcr_slots |= selected_pcr_slots;
                previously_selected_pcr_slots.extend_from_slice(pcr_slots);
            }
            None => {
                let _ = self.items.insert(hash_algorithm, pcr_slots.to_vec());
            }
        }
        self
    }

    /// Builds a PcrSelections with the values that have been
    /// provided.
    ///
    /// If no size of select have been provided then it will
    /// be defaulted to to the most suitable with regard to TPM2_PCR_SELECT_MAX.
    /// This may not be the correct size for
    /// the current platform. The correct values can be obtained
    /// by querying the tpm for its capabilities.
    pub fn build(self) -> Result<PcrSelectionList> {
        let size_of_select = self.size_of_select.unwrap_or_default();
        self.items
            .iter()
            .try_fold(Vec::<PcrSelection>::new(), |mut acc, (&k, v)| {
                PcrSelection::create(k, size_of_select, v.as_slice()).map(|pcr_select| {
                    acc.push(pcr_select);
                    acc
                })
            })
            .map(|items| PcrSelectionList { items })
    }
}
