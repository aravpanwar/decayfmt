// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::PropertyTag,
    structures::TaggedProperty,
    tss2_esys::{TPML_TAGGED_TPM_PROPERTY, TPMS_TAGGED_PROPERTY},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{convert::TryFrom, iter::IntoIterator, ops::Deref};

/// A structure holding a list of tagged tpm properties.
///
/// # Details
/// This corresponds to the TPML_TAGGED_TPM_PROPERTY strucutre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedTpmPropertyList {
    tagged_tpm_properties: Vec<TaggedProperty>,
}

impl TaggedTpmPropertyList {
    pub const MAX_SIZE: usize = Self::calculate_max_size();

    /// Finds the first [TaggedProperty] in the list matching the provided `property_tag`.
    pub fn find(&self, property_tag: PropertyTag) -> Option<&TaggedProperty> {
        self.tagged_tpm_properties
            .iter()
            .find(|tp| tp.property() == property_tag)
    }

    /// Private function that calculates the maximum number
    /// elements allowed in internal storage.
    const fn calculate_max_size() -> usize {
        crate::structures::capability_data::max_cap_size::<TPMS_TAGGED_PROPERTY>()
    }
}

impl Deref for TaggedTpmPropertyList {
    type Target = Vec<TaggedProperty>;

    fn deref(&self) -> &Self::Target {
        &self.tagged_tpm_properties
    }
}

impl AsRef<[TaggedProperty]> for TaggedTpmPropertyList {
    fn as_ref(&self) -> &[TaggedProperty] {
        self.tagged_tpm_properties.as_slice()
    }
}

impl TryFrom<Vec<TaggedProperty>> for TaggedTpmPropertyList {
    type Error = Error;

    fn try_from(tagged_tpm_properties: Vec<TaggedProperty>) -> Result<Self> {
        if tagged_tpm_properties.len() > Self::MAX_SIZE {
            error!("Failed to convert Vec<TaggedProperty> into TaggedTpmPropertyList, to many items (> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(TaggedTpmPropertyList {
            tagged_tpm_properties,
        })
    }
}

impl IntoIterator for TaggedTpmPropertyList {
    type Item = TaggedProperty;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.tagged_tpm_properties.into_iter()
    }
}

impl TryFrom<TPML_TAGGED_TPM_PROPERTY> for TaggedTpmPropertyList {
    type Error = Error;

    fn try_from(tpml_tagged_tpm_property: TPML_TAGGED_TPM_PROPERTY) -> Result<Self> {
        let count = usize::try_from(tpml_tagged_tpm_property.count).map_err(|e| {
            error!(
                "Failed to parse count in TPML_TAGGED_TPM_PROPERTY as usize: {}",
                e
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        if count > Self::MAX_SIZE {
            error!(
                "Invalid size value in TPML_TAGGED_TPM_PROPERTY (> {})",
                Self::MAX_SIZE,
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        tpml_tagged_tpm_property.tpmProperty[..count]
            .iter()
            .map(|&tp| TaggedProperty::try_from(tp))
            .collect::<Result<Vec<TaggedProperty>>>()
            .map(|tagged_tpm_properties| TaggedTpmPropertyList {
                tagged_tpm_properties,
            })
    }
}

impl From<TaggedTpmPropertyList> for TPML_TAGGED_TPM_PROPERTY {
    fn from(tagged_tpm_property_list: TaggedTpmPropertyList) -> Self {
        let mut tpml_tagged_tpm_property: TPML_TAGGED_TPM_PROPERTY = Default::default();
        for tagged_property in tagged_tpm_property_list {
            tpml_tagged_tpm_property.tpmProperty[tpml_tagged_tpm_property.count as usize] =
                tagged_property.into();
            tpml_tagged_tpm_property.count += 1;
        }
        tpml_tagged_tpm_property
    }
}
