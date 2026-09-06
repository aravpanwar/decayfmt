// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::PcrPropertyTag,
    structures::{PcrSlot, TaggedPcrSelect},
    tss2_esys::{TPML_TAGGED_PCR_PROPERTY, TPMS_TAGGED_PCR_SELECT},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{convert::TryFrom, iter::IntoIterator, ops::Deref};
/// A structure holding a list of tagged pcr properties.
///
/// # Details
/// This corresponds to the TPML_TAGGED_PCR_PROPERTY structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedPcrPropertyList {
    tagged_pcr_properties: Vec<TaggedPcrSelect>,
}

impl TaggedPcrPropertyList {
    pub const MAX_SIZE: usize = Self::calculate_max_size();

    /// Finds the first [TaggedPcrSelect] in the list that matches the provided `pcr_property_tag`.
    pub fn find(&self, pcr_property_tag: PcrPropertyTag) -> Option<&TaggedPcrSelect> {
        self.tagged_pcr_properties
            .iter()
            .find(|tps| tps.pcr_property_tag() == pcr_property_tag)
    }

    /// Returns a collection [TaggedPcrSelect] references in which each referenced items
    /// has the specified [PcrSlot] selected.
    pub fn find_pcr_slot(&self, pcr_slot: PcrSlot) -> Vec<&TaggedPcrSelect> {
        self.tagged_pcr_properties
            .iter()
            .fold(Vec::<&TaggedPcrSelect>::new(), |mut acc, tps| {
                if tps.selected_pcrs().contains(&pcr_slot) {
                    acc.push(tps);
                }
                acc
            })
    }

    /// Private function that calculates the maximum number
    /// elements allowed in internal storage.
    const fn calculate_max_size() -> usize {
        crate::structures::capability_data::max_cap_size::<TPMS_TAGGED_PCR_SELECT>()
    }
}

impl Deref for TaggedPcrPropertyList {
    type Target = Vec<TaggedPcrSelect>;

    fn deref(&self) -> &Self::Target {
        &self.tagged_pcr_properties
    }
}

impl AsRef<[TaggedPcrSelect]> for TaggedPcrPropertyList {
    fn as_ref(&self) -> &[TaggedPcrSelect] {
        self.tagged_pcr_properties.as_slice()
    }
}

impl TryFrom<Vec<TaggedPcrSelect>> for TaggedPcrPropertyList {
    type Error = Error;

    fn try_from(tagged_pcr_properties: Vec<TaggedPcrSelect>) -> Result<Self> {
        if tagged_pcr_properties.len() > Self::MAX_SIZE {
            error!("Failed to convert Vec<TaggedPcrSelect> into TaggedPcrPropertyList, to many items (> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(TaggedPcrPropertyList {
            tagged_pcr_properties,
        })
    }
}

impl IntoIterator for TaggedPcrPropertyList {
    type Item = TaggedPcrSelect;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.tagged_pcr_properties.into_iter()
    }
}

impl TryFrom<TPML_TAGGED_PCR_PROPERTY> for TaggedPcrPropertyList {
    type Error = Error;

    fn try_from(tpml_tagged_pcr_property: TPML_TAGGED_PCR_PROPERTY) -> Result<Self> {
        let count = usize::try_from(tpml_tagged_pcr_property.count).map_err(|e| {
            error!(
                "Failed to parse count in TPML_TAGGED_PCR_PROPERTY as usize: {}",
                e
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        if count > Self::MAX_SIZE {
            error!(
                "Invalid size value in TPML_TAGGED_PCR_PROPERTY (> {})",
                Self::MAX_SIZE,
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        tpml_tagged_pcr_property.pcrProperty[..count]
            .iter()
            .map(|&tp| TaggedPcrSelect::try_from(tp))
            .collect::<Result<Vec<TaggedPcrSelect>>>()
            .map(|tagged_pcr_properties| TaggedPcrPropertyList {
                tagged_pcr_properties,
            })
    }
}

impl From<TaggedPcrPropertyList> for TPML_TAGGED_PCR_PROPERTY {
    fn from(tagged_pcr_property_list: TaggedPcrPropertyList) -> Self {
        let mut tpml_tagged_pcr_property = TPML_TAGGED_PCR_PROPERTY::default();
        for tagged_pcr_select in tagged_pcr_property_list {
            tpml_tagged_pcr_property.pcrProperty[tpml_tagged_pcr_property.count as usize] =
                tagged_pcr_select.into();
            tpml_tagged_pcr_property.count += 1;
        }
        tpml_tagged_pcr_property
    }
}
