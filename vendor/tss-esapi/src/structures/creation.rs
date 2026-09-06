// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    attributes::LocalityAttributes,
    constants::AlgorithmIdentifier,
    interface_types::algorithm::HashingAlgorithm,
    structures::{Data, Digest, Name, PcrSelectionList},
    tss2_esys::{TPM2B_CREATION_DATA, TPMS_CREATION_DATA},
    Error, Result,
};
use std::convert::{TryFrom, TryInto};

#[derive(Debug, Clone)]
pub struct CreationData {
    pcr_select: PcrSelectionList,
    pcr_digest: Digest,
    locality: LocalityAttributes,
    parent_name_alg: Option<HashingAlgorithm>,
    parent_name: Name,
    parent_qualified_name: Name,
    outside_info: Data,
}

impl TryFrom<TPMS_CREATION_DATA> for CreationData {
    type Error = Error;
    fn try_from(tss_creation_data: TPMS_CREATION_DATA) -> Result<Self> {
        Ok(CreationData {
            pcr_select: tss_creation_data.pcrSelect.try_into()?,
            pcr_digest: tss_creation_data.pcrDigest.try_into()?,
            locality: tss_creation_data.locality.into(),
            parent_name_alg: match AlgorithmIdentifier::try_from(tss_creation_data.parentNameAlg)? {
                AlgorithmIdentifier::Null => None,
                alg => Some(HashingAlgorithm::try_from(alg)?),
            },
            parent_name: tss_creation_data.parentName.try_into()?,
            parent_qualified_name: tss_creation_data.parentQualifiedName.try_into()?,
            outside_info: tss_creation_data.outsideInfo.try_into()?,
        })
    }
}

impl TryFrom<TPM2B_CREATION_DATA> for CreationData {
    type Error = Error;
    fn try_from(tss_creation_data_buffer: TPM2B_CREATION_DATA) -> Result<Self> {
        CreationData::try_from(tss_creation_data_buffer.creationData)
    }
}

impl From<CreationData> for TPMS_CREATION_DATA {
    fn from(creation_data: CreationData) -> Self {
        TPMS_CREATION_DATA {
            pcrSelect: creation_data.pcr_select.into(),
            pcrDigest: creation_data.pcr_digest.into(),
            locality: creation_data.locality.into(),
            parentNameAlg: match creation_data.parent_name_alg {
                None => AlgorithmIdentifier::Null.into(),
                Some(alg) => alg.into(),
            },
            parentName: creation_data.parent_name.into(),
            parentQualifiedName: creation_data.parent_qualified_name.into(),
            outsideInfo: creation_data.outside_info.into(),
        }
    }
}
