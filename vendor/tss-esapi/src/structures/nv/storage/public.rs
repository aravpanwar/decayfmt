// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    attributes::NvIndexAttributes,
    handles::NvIndexTpmHandle,
    interface_types::algorithm::HashingAlgorithm,
    structures::Digest,
    tss2_esys::{TPM2B_NV_PUBLIC, TPMS_NV_PUBLIC},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
};

/// Representation of the public parameters of a non-volatile
/// space allocation.
///
/// # Details
/// Corresponds to `TPMS_NV_PUBLIC`
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NvPublic {
    nv_index: NvIndexTpmHandle,
    name_algorithm: HashingAlgorithm,
    attributes: NvIndexAttributes,
    authorization_policy: Digest,
    data_size: usize,
}

impl NvPublic {
    const MAX_SIZE: usize = size_of::<TPMS_NV_PUBLIC>();

    pub fn nv_index(&self) -> NvIndexTpmHandle {
        self.nv_index
    }

    pub fn name_algorithm(&self) -> HashingAlgorithm {
        self.name_algorithm
    }

    pub fn attributes(&self) -> NvIndexAttributes {
        self.attributes
    }

    pub fn authorization_policy(&self) -> &Digest {
        &self.authorization_policy
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    /// Get a builder for the structure
    pub const fn builder() -> NvPublicBuilder {
        NvPublicBuilder::new()
    }
}

impl TryFrom<TPM2B_NV_PUBLIC> for NvPublic {
    type Error = Error;
    fn try_from(tss_nv_public: TPM2B_NV_PUBLIC) -> Result<NvPublic> {
        if tss_nv_public.size as usize > NvPublic::MAX_SIZE {
            error!("Encountered an invalid size of the TPMS_NV_PUBLIC");
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        // Parse actual data
        Ok(NvPublic {
            nv_index: tss_nv_public.nvPublic.nvIndex.try_into()?,
            name_algorithm: tss_nv_public.nvPublic.nameAlg.try_into()?,
            attributes: tss_nv_public.nvPublic.attributes.try_into()?,
            authorization_policy: tss_nv_public.nvPublic.authPolicy.try_into()?,
            data_size: tss_nv_public.nvPublic.dataSize as usize,
        })
    }
}

impl TryFrom<NvPublic> for TPM2B_NV_PUBLIC {
    type Error = Error;
    fn try_from(nv_public: NvPublic) -> Result<TPM2B_NV_PUBLIC> {
        Ok(TPM2B_NV_PUBLIC {
            // Will be ignored due to being a complex TPM2B type
            // The marshalling functionality in TSS will calculate
            // the correct value.
            size: 0,
            nvPublic: TPMS_NV_PUBLIC {
                nvIndex: nv_public.nv_index.into(),
                nameAlg: nv_public.name_algorithm.into(),
                attributes: nv_public.attributes.try_into()?,
                authPolicy: nv_public.authorization_policy.into(),
                dataSize: nv_public.data_size as u16,
            },
        })
    }
}

/// Builder for NvPublic.
///
///
#[derive(Debug, Default)]
pub struct NvPublicBuilder {
    nv_index: Option<NvIndexTpmHandle>,
    name_algorithm: Option<HashingAlgorithm>,
    attributes: Option<NvIndexAttributes>,
    authorization_policy: Option<Digest>,
    data_size: Option<usize>,
}

impl NvPublicBuilder {
    pub const fn new() -> Self {
        NvPublicBuilder {
            nv_index: None,
            name_algorithm: None,
            attributes: None,
            authorization_policy: None,
            data_size: None,
        }
    }

    pub fn with_nv_index(mut self, nv_index: NvIndexTpmHandle) -> Self {
        self.nv_index = Some(nv_index);
        self
    }

    pub fn with_index_name_algorithm(mut self, nv_index_name_algorithm: HashingAlgorithm) -> Self {
        self.name_algorithm = Some(nv_index_name_algorithm);
        self
    }

    pub fn with_index_attributes(mut self, nv_index_attributes: NvIndexAttributes) -> Self {
        self.attributes = Some(nv_index_attributes);
        self
    }

    pub fn with_index_auth_policy(mut self, nv_index_auth_policy: Digest) -> Self {
        self.authorization_policy = Some(nv_index_auth_policy);
        self
    }

    pub fn with_data_area_size(mut self, nv_index_data_area_size: usize) -> Self {
        self.data_size = Some(nv_index_data_area_size);
        self
    }

    pub fn build(self) -> Result<NvPublic> {
        // TODO: Do some clever checking of the values in
        // order to determine some defaults values when
        // some params have not been specified.
        //

        Ok(NvPublic {
            // Nv Index
            nv_index: self.nv_index.ok_or_else(|| {
                error!("No NV index was specified");
                Error::local_error(WrapperErrorKind::ParamsMissing)
            })?,
            // Hashing algorithm for the name of index
            name_algorithm: self.name_algorithm.ok_or_else(|| {
                error!("No name algorithm was specified");
                Error::local_error(WrapperErrorKind::ParamsMissing)
            })?,
            // Index attributes
            attributes: self.attributes.ok_or_else(|| {
                error!("No attributes were specified");
                Error::local_error(WrapperErrorKind::ParamsMissing)
            })?,
            // Index Auth policy
            authorization_policy: self.authorization_policy.unwrap_or_default(),
            // Size of the data area of the index
            data_size: self
                .data_size
                .ok_or_else(|| {
                    error!("No data size specified");
                    Error::local_error(WrapperErrorKind::ParamsMissing)
                })
                .and_then(|v| {
                    if v > u16::MAX.into() {
                        error!("data area size is too large (>{})", u16::MAX);
                        return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                    }
                    Ok(v)
                })?,
        })
    }
}
