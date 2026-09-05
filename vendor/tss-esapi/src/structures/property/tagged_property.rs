// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{constants::PropertyTag, tss2_esys::TPMS_TAGGED_PROPERTY, Error, Result};
use std::convert::TryFrom;

/// Struct representing a tagged property
///
/// # Details
/// This corresponds to TPMS_TAGGED_PROPERTY
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TaggedProperty {
    property: PropertyTag,
    value: u32,
}

impl TaggedProperty {
    /// Creates a new TaggedProperty
    pub const fn new(property: PropertyTag, value: u32) -> Self {
        TaggedProperty { property, value }
    }

    /// Returns the property tag
    pub const fn property(&self) -> PropertyTag {
        self.property
    }

    /// Returns the value
    pub const fn value(&self) -> u32 {
        self.value
    }
}

impl TryFrom<TPMS_TAGGED_PROPERTY> for TaggedProperty {
    type Error = Error;

    fn try_from(tpms_tagged_property: TPMS_TAGGED_PROPERTY) -> Result<Self> {
        let value = tpms_tagged_property.value;
        PropertyTag::try_from(tpms_tagged_property.property)
            .map(|property| TaggedProperty { property, value })
    }
}

impl From<TaggedProperty> for TPMS_TAGGED_PROPERTY {
    fn from(tagged_property: TaggedProperty) -> Self {
        TPMS_TAGGED_PROPERTY {
            property: tagged_property.property.into(),
            value: tagged_property.value,
        }
    }
}
