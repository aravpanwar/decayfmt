// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::AlgorithmIdentifier,
    structures::AlgorithmProperty,
    tss2_esys::{TPML_ALG_PROPERTY, TPMS_ALG_PROPERTY},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{convert::TryFrom, iter::IntoIterator, ops::Deref};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmPropertyList {
    algorithm_properties: Vec<AlgorithmProperty>,
}

impl AlgorithmPropertyList {
    pub const MAX_SIZE: usize = Self::calculate_max_size();

    /// Finds an [AlgorithmProperty] in the list that matches
    /// the provided ´algorithm_identifier´.
    pub fn find(&self, algorithm_identifier: AlgorithmIdentifier) -> Option<&AlgorithmProperty> {
        self.algorithm_properties
            .iter()
            .find(|ap| ap.algorithm_identifier() == algorithm_identifier)
    }

    /// Private function that calculates the maximum number
    /// elements allowed in internal storage.
    const fn calculate_max_size() -> usize {
        crate::structures::capability_data::max_cap_size::<TPMS_ALG_PROPERTY>()
    }
}

impl Deref for AlgorithmPropertyList {
    type Target = Vec<AlgorithmProperty>;

    fn deref(&self) -> &Self::Target {
        &self.algorithm_properties
    }
}

impl AsRef<[AlgorithmProperty]> for AlgorithmPropertyList {
    fn as_ref(&self) -> &[AlgorithmProperty] {
        self.algorithm_properties.as_slice()
    }
}

impl IntoIterator for AlgorithmPropertyList {
    type Item = AlgorithmProperty;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.algorithm_properties.into_iter()
    }
}

impl TryFrom<Vec<AlgorithmProperty>> for AlgorithmPropertyList {
    type Error = Error;

    fn try_from(algorithm_properties: Vec<AlgorithmProperty>) -> Result<Self> {
        if algorithm_properties.len() > Self::MAX_SIZE {
            error!("Failed to convert Vec<AlgorithmProperty> into AlgorithmPropertyList, to many items (> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(AlgorithmPropertyList {
            algorithm_properties,
        })
    }
}

impl From<AlgorithmPropertyList> for Vec<AlgorithmProperty> {
    fn from(algorithm_property_list: AlgorithmPropertyList) -> Self {
        algorithm_property_list.algorithm_properties
    }
}

impl TryFrom<TPML_ALG_PROPERTY> for AlgorithmPropertyList {
    type Error = Error;

    fn try_from(tpml_alg_property: TPML_ALG_PROPERTY) -> Result<Self> {
        let count = usize::try_from(tpml_alg_property.count).map_err(|e| {
            error!("Failed to parse count in TPML_ALG_PROPERTY as usize: {}", e);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        if count > Self::MAX_SIZE {
            error!(
                "Invalid size value in TPML_ALG_PROPERTY (> {})",
                Self::MAX_SIZE,
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        tpml_alg_property.algProperties[..count]
            .iter()
            .map(|&tp| AlgorithmProperty::try_from(tp))
            .collect::<Result<Vec<AlgorithmProperty>>>()
            .map(|algorithm_properties| AlgorithmPropertyList {
                algorithm_properties,
            })
    }
}

impl From<AlgorithmPropertyList> for TPML_ALG_PROPERTY {
    fn from(algorithm_property_list: AlgorithmPropertyList) -> Self {
        let mut tpml_alg_property: TPML_ALG_PROPERTY = Default::default();
        for algorithm_property in algorithm_property_list {
            tpml_alg_property.algProperties[tpml_alg_property.count as usize] =
                algorithm_property.into();
            tpml_alg_property.count += 1;
        }
        tpml_alg_property
    }
}
