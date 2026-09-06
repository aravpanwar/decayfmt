// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{tss2_esys::TPMA_LOCALITY, Error, Result, WrapperErrorKind};
use bitfield::bitfield;
use log::error;

bitfield! {
    /// Bitfield representing the locality attributes.
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct LocalityAttributes(TPMA_LOCALITY);
    impl Debug;

    _, set_locality_zero: 0;
    pub locality_zero, _: 0;
    _, set_locality_one: 1;
    pub locality_one, _: 1;
    _, set_locality_two: 2;
    pub locality_two, _: 2;
    _, set_locality_three: 3;
    pub locality_three, _: 3;
    _, set_locality_four: 4;
    pub locality_four, _: 4;
    _, set_extended: 7, 5;
    extended, _: 7, 5;
}

impl LocalityAttributes {
    pub const LOCALITY_ZERO: LocalityAttributes = LocalityAttributes(1);
    pub const LOCALITY_ONE: LocalityAttributes = LocalityAttributes(2);
    pub const LOCALITY_TWO: LocalityAttributes = LocalityAttributes(4);
    pub const LOCALITY_THREE: LocalityAttributes = LocalityAttributes(8);
    pub const LOCALITY_FOUR: LocalityAttributes = LocalityAttributes(16);
    /// Returns true if the attributes are extended
    pub fn is_extended(&self) -> bool {
        self.extended() != 0u8
    }

    /// Returns the LocalityAttributes as a number.
    ///
    /// # Errors
    /// If the attributes are not extended en InvalidParams error
    /// is returned.
    pub fn as_extended(&self) -> Result<u8> {
        if self.is_extended() {
            Ok(self.0)
        } else {
            error!("Cannot retrieve LocalityAttributes as extended when the attributes are not indicated to be extended");
            Err(Error::local_error(WrapperErrorKind::InvalidParam))
        }
    }

    /// Returns the builder used to construct LocalAttributes.
    pub const fn builder() -> LocalityAttributesBuilder {
        LocalityAttributesBuilder::new()
    }
}

impl From<TPMA_LOCALITY> for LocalityAttributes {
    fn from(tpma_locality: TPMA_LOCALITY) -> Self {
        LocalityAttributes(tpma_locality)
    }
}

impl From<LocalityAttributes> for TPMA_LOCALITY {
    fn from(locality_attributes: LocalityAttributes) -> Self {
        locality_attributes.0
    }
}

#[derive(Debug, Clone)]
pub struct LocalityAttributesBuilder {
    localities: Vec<u8>,
}

impl LocalityAttributesBuilder {
    /// Creates a new builder.
    pub const fn new() -> Self {
        LocalityAttributesBuilder {
            localities: Vec::new(),
        }
    }
    /// Adds a locality to the builder
    pub fn with_locality(mut self, locality: u8) -> Self {
        self.localities.push(locality);
        self
    }

    /// Adds a slice of localities to the builder
    pub fn with_localities(mut self, localities: &[u8]) -> Self {
        self.localities.extend_from_slice(localities);
        self
    }

    /// Builds the attributes
    pub fn build(self) -> Result<LocalityAttributes> {
        let mut locality_attributes = LocalityAttributes(0);
        for locality in self.localities {
            if locality_attributes.is_extended() {
                error!("Locality attribute {new} and locality attribute {prev} cannot be combined because locality attribute {prev} is extended", new=locality, prev=locality_attributes.0);
                return Err(Error::local_error(WrapperErrorKind::InvalidParam));
            }
            match locality {
                0 => locality_attributes.set_locality_zero(true),
                1 => locality_attributes.set_locality_one(true),
                2 => locality_attributes.set_locality_two(true),
                3 => locality_attributes.set_locality_three(true),
                4 => locality_attributes.set_locality_four(true),
                5..=31 => {
                    error!(
                        "Locality attribute {new} is invalid and cannot be combined with other locality attributes",
                        new=locality
                    );
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }
                32..=255 => {
                    if locality_attributes.0 != 0 {
                        error!("Locality attribute {new} is extended and cannot be combined with locality attribute(s) {old}", new=locality, old=locality_attributes.0);
                        return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                    }
                    locality_attributes.0 = locality;
                }
            }
        }
        Ok(locality_attributes)
    }
}

impl Default for LocalityAttributesBuilder {
    fn default() -> Self {
        Self::new()
    }
}
