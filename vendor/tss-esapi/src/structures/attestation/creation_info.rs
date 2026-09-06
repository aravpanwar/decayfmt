// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::{Digest, Name},
    tss2_esys::TPMS_CREATION_INFO,
    Error, Result,
};
use std::convert::{TryFrom, TryInto};
/// Structure holding the attested data for TPM2_CertifyCreation()
///
/// # Details
/// This corresponds to the TPMS_CREATION_INFO
#[derive(Debug, Clone)]
pub struct CreationInfo {
    object_name: Name,
    creation_hash: Digest,
}

impl CreationInfo {
    /// Returns the name of the object
    pub const fn object_name(&self) -> &Name {
        &self.object_name
    }

    /// Returns the creation hash
    pub const fn creation_hash(&self) -> &Digest {
        &self.creation_hash
    }
}

impl From<CreationInfo> for TPMS_CREATION_INFO {
    fn from(creation_info: CreationInfo) -> Self {
        TPMS_CREATION_INFO {
            objectName: creation_info.object_name.into(),
            creationHash: creation_info.creation_hash.into(),
        }
    }
}

impl TryFrom<TPMS_CREATION_INFO> for CreationInfo {
    type Error = Error;

    fn try_from(tpms_creation_info: TPMS_CREATION_INFO) -> Result<Self> {
        Ok(CreationInfo {
            object_name: tpms_creation_info.objectName.try_into()?,
            creation_hash: tpms_creation_info.creationHash.try_into()?,
        })
    }
}
