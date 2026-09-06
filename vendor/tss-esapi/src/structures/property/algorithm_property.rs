// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    attributes::AlgorithmAttributes, constants::AlgorithmIdentifier, tss2_esys::TPMS_ALG_PROPERTY,
    Error, Result,
};
use std::convert::{TryFrom, TryInto};

/// Strucutre for holding information describing an
/// algorithm.
///
/// # Details
/// This corresponds to the TPMS_ALG_PROPERTY
/// structure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmProperty {
    algorithm_identifier: AlgorithmIdentifier,
    algorithm_properties: AlgorithmAttributes,
}

impl AlgorithmProperty {
    /// Creates a new AlgorithmProperty with the
    /// given parameters.
    pub const fn new(
        algorithm_identifier: AlgorithmIdentifier,
        algorithm_properties: AlgorithmAttributes,
    ) -> Self {
        AlgorithmProperty {
            algorithm_identifier,
            algorithm_properties,
        }
    }

    /// Returns the algorithm identifier
    pub const fn algorithm_identifier(&self) -> AlgorithmIdentifier {
        self.algorithm_identifier
    }

    /// Returns the algorithm properties
    pub const fn algorithm_properties(&self) -> AlgorithmAttributes {
        self.algorithm_properties
    }
}

impl TryFrom<TPMS_ALG_PROPERTY> for AlgorithmProperty {
    type Error = Error;

    fn try_from(tpms_algorithm_description: TPMS_ALG_PROPERTY) -> Result<Self> {
        Ok(AlgorithmProperty {
            algorithm_identifier: tpms_algorithm_description.alg.try_into()?,
            algorithm_properties: tpms_algorithm_description.algProperties.into(),
        })
    }
}

impl From<AlgorithmProperty> for TPMS_ALG_PROPERTY {
    fn from(algorithm_description: AlgorithmProperty) -> Self {
        TPMS_ALG_PROPERTY {
            alg: algorithm_description.algorithm_identifier.into(),
            algProperties: algorithm_description.algorithm_properties.into(),
        }
    }
}
