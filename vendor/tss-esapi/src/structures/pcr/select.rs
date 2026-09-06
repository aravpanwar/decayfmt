// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    structures::{PcrSelectSize, PcrSlot, PcrSlotCollection},
    tss2_esys::TPMS_PCR_SELECT,
    Error, Result,
};

use std::convert::TryFrom;
/// This module contains necessary representations
/// of the items belonging to the TPMS_PCR_SELECT
/// structure.
///
/// The minimum number of octets allowed in a TPMS_PCR_SELECT.sizeOfSelect
/// is not determined by the number of PCR implemented but by the
/// number of PCR required by the platform-specific
/// specification with which the TPM is compliant or by the implementer if
/// not adhering to a platform-specific specification.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PcrSelect {
    pcr_slot_collection: PcrSlotCollection,
}

impl PcrSelect {
    /// Creates a new PcrSelect
    pub fn create(pcr_select_size: PcrSelectSize, pcr_slots: &[PcrSlot]) -> Result<Self> {
        PcrSlotCollection::create(pcr_select_size, pcr_slots).map(|pcr_slot_collection| PcrSelect {
            pcr_slot_collection,
        })
    }

    /// Returns the size of the select.
    ///
    /// NB! This is not the same as how many [PcrSlot]
    /// there are in the select but rather how many
    /// octets that are needed to hold the bit field
    /// that indicate what slots that are selected.
    pub fn size_of_select(&self) -> PcrSelectSize {
        self.pcr_slot_collection.size_of_select()
    }

    /// Returns the selected PCRs in the select.
    pub fn selected_pcrs(&self) -> Vec<PcrSlot> {
        self.pcr_slot_collection.collection()
    }
}

impl TryFrom<TPMS_PCR_SELECT> for PcrSelect {
    type Error = Error;
    fn try_from(tss_pcr_select: TPMS_PCR_SELECT) -> Result<Self> {
        PcrSlotCollection::try_from((tss_pcr_select.sizeofSelect, tss_pcr_select.pcrSelect)).map(
            |pcr_slot_collection| PcrSelect {
                pcr_slot_collection,
            },
        )
    }
}

impl From<PcrSelect> for TPMS_PCR_SELECT {
    fn from(pcr_select: PcrSelect) -> Self {
        let (size_of_select, pcr_select) = pcr_select.pcr_slot_collection.into();
        TPMS_PCR_SELECT {
            sizeofSelect: size_of_select,
            pcrSelect: pcr_select,
        }
    }
}
