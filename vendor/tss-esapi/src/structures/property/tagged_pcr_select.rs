// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::PcrPropertyTag,
    structures::{PcrSelectSize, PcrSlot, PcrSlotCollection},
    tss2_esys::TPMS_TAGGED_PCR_SELECT,
    Error, Result,
};

use std::convert::TryFrom;

/// Type that holds information regarding
/// what PCR slots that are associated with
/// a specific pcr property tag.
///
/// This corresponds to the TPMS_TAGGED_PCR_SELECT.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TaggedPcrSelect {
    pcr_property_tag: PcrPropertyTag,
    pcr_slot_collection: PcrSlotCollection,
}

impl TaggedPcrSelect {
    /// Creates a new TaggedPcrSelect
    pub fn create(
        pcr_property_tag: PcrPropertyTag,
        pcr_select_size: PcrSelectSize,
        selected_pcr_slots: &[PcrSlot],
    ) -> Result<Self> {
        PcrSlotCollection::create(pcr_select_size, selected_pcr_slots).map(|pcr_slot_collection| {
            TaggedPcrSelect {
                pcr_property_tag,
                pcr_slot_collection,
            }
        })
    }

    /// Returns the property identifier
    pub const fn pcr_property_tag(&self) -> PcrPropertyTag {
        self.pcr_property_tag
    }

    /// Returns the size of the select
    ///
    /// NB! This is not the same as how many [PcrSlot]
    /// there are in the select, but rather how many
    /// octets are needed to hold the bit field which
    /// indicates what slots have the [PcrPropertyTag]
    /// property.
    pub const fn size_of_select(&self) -> PcrSelectSize {
        self.pcr_slot_collection.size_of_select()
    }

    /// Returns the pcr slots that has the property
    /// indicated by the pcr property tag.
    pub fn selected_pcrs(&self) -> Vec<PcrSlot> {
        self.pcr_slot_collection.collection()
    }
}

impl TryFrom<TPMS_TAGGED_PCR_SELECT> for TaggedPcrSelect {
    type Error = Error;
    fn try_from(tpms_tagged_pcr_select: TPMS_TAGGED_PCR_SELECT) -> Result<Self> {
        // Parse the tag.
        let pcr_property_tag = PcrPropertyTag::try_from(tpms_tagged_pcr_select.tag)?;
        let pcr_slot_collection = PcrSlotCollection::try_from((
            tpms_tagged_pcr_select.sizeofSelect,
            tpms_tagged_pcr_select.pcrSelect,
        ))?;

        Ok(TaggedPcrSelect {
            pcr_property_tag,
            pcr_slot_collection,
        })
    }
}

impl From<TaggedPcrSelect> for TPMS_TAGGED_PCR_SELECT {
    fn from(tagged_pcr_select: TaggedPcrSelect) -> Self {
        let (size_of_select, pcr_select) = tagged_pcr_select.pcr_slot_collection.into();
        TPMS_TAGGED_PCR_SELECT {
            tag: tagged_pcr_select.pcr_property_tag.into(),
            sizeofSelect: size_of_select,
            pcrSelect: pcr_select,
        }
    }
}
