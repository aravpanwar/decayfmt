// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::NvIndexType,
    tss2_esys::{TPM2_NT, TPMA_NV},
    Error, Result, WrapperErrorKind,
};

use bitfield::bitfield;
use log::error;
use std::convert::TryFrom;

bitfield! {
    /// Bitfield representing the nv index attributes.
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct NvIndexAttributes(TPMA_NV);
    impl Debug;
    // NV Index Attributes
    pub pp_write, _: 0;
    _, set_pp_write: 0;
    pub owner_write, _: 1;
    _, set_owner_write: 1;
    pub auth_write, _: 2;
    _, set_auth_write: 2;
    pub policy_write, _: 3;
    _, set_policy_write: 3;
    TPM2_NT, tss_index_type, _: 7, 4; // private getter
    TPM2_NT, from into NvIndexType, _, set_index_type: 7, 4;
    // Reserved 9,8
    pub policy_delete, _: 10;
    _, set_policy_delete: 10;
    pub write_locked, _: 11;
    _, set_write_locked: 11;
    pub write_all, _: 12;
    _, set_write_all: 12;
    pub write_define, _: 13;
    _, set_write_define: 13;
    pub write_stclear, _: 14;
    _, set_write_stclear: 14;
    pub global_lock, _: 15;
    _, set_global_lock: 15;
    pub pp_read, _: 16;
    _, set_pp_read: 16;
    pub owner_read, _: 17;
    _, set_owner_read: 17;
    pub auth_read, _: 18;
    _, set_auth_read: 18;
    pub policy_read, _: 19;
    _, set_policy_read: 19;
    // Reserved 24, 20
    pub no_da, _: 25;
    _, set_no_da: 25;
    pub orderly, _: 26;
    _, set_orderly: 26;
    pub clear_stclear, _: 27;
    _, set_clear_stclear: 27;
    pub read_locked, _: 28;
    _, set_read_locked: 28;
    pub written, _: 29;
    _, set_written: 29;
    pub platform_create, _: 30;
    _, set_platform_create: 30;
    pub read_stclear, _: 31;
    _, set_read_stclear: 31;
}

impl NvIndexAttributes {
    /// Returns the `NvIndexType` of the `NvIndexAttributes`
    pub fn index_type(&self) -> Result<NvIndexType> {
        NvIndexType::try_from(self.tss_index_type())
    }

    /// Validates the attributes
    ///
    /// # Details
    /// Performs checks on `self` in order to verify
    /// that the attributes conforms to the requirements
    /// specified in the standard.
    ///
    /// # Errors
    /// Returns an error if some attributes are missing
    /// or are in conflict with each other.
    pub fn validate(&self) -> Result<()> {
        // "At least one of TPMA_NV_PPREAD, TPMA_NV_OWNERREAD,
        // TPMA_NV_AUTHREAD, or TPMA_NV_POLICYREAD shall be SET."
        if !(self.pp_read() | self.owner_read() | self.auth_read() | self.policy_read()) {
            error!("Non of the attributes PPREAD, OWERREAD, AUTHREAD, POLICYREAD have been set");
            return Err(Error::local_error(WrapperErrorKind::ParamsMissing));
        }

        // "At least one of TPMA_NV_PPWRITE, TPMA_NV_OWNERWRITE,
        // TPMA_NV_AUTHWRITE, or TPMA_NV_POLICYWRITE shall be SET."
        if !(self.pp_write() | self.owner_write() | self.auth_write() | self.policy_write()) {
            error!(
                "Non of the attributes PPWRITE, OWNERWRITE, AUTHWRITE, POLICYWRITE have been set"
            );
            return Err(Error::local_error(WrapperErrorKind::ParamsMissing));
        }

        // "If TPM_NT is TPM_NT_PIN_FAIL, TPMA_NV_NO_DA must be SET.
        // This removes ambiguity over which Dictionary Attack defense
        // protects a TPM_NV_PIN_FAIL's authValue."
        if (self.index_type()? == NvIndexType::PinFail) & !self.no_da() {
            error!("NvIndexType was PinFail but `no DA` attribute was not set");
            return Err(Error::local_error(WrapperErrorKind::ParamsMissing));
        }

        Ok(())
    }

    /// Get a builder for the structure
    pub const fn builder() -> NvIndexAttributesBuilder {
        NvIndexAttributesBuilder::new()
    }
}

impl TryFrom<TPMA_NV> for NvIndexAttributes {
    type Error = Error;

    fn try_from(tss_nv_index_atttributes: TPMA_NV) -> Result<NvIndexAttributes> {
        let nv_index_attributes = NvIndexAttributes(tss_nv_index_atttributes);
        nv_index_attributes.validate()?;
        Ok(nv_index_attributes)
    }
}

impl TryFrom<NvIndexAttributes> for TPMA_NV {
    type Error = Error;
    fn try_from(nv_index_atttributes: NvIndexAttributes) -> Result<TPMA_NV> {
        nv_index_atttributes.validate()?;
        Ok(nv_index_atttributes.0)
    }
}

/// A builder NV index attributes
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NvIndexAttributesBuilder {
    nv_index_attributes: NvIndexAttributes,
}

impl NvIndexAttributesBuilder {
    /// Creates a new nv index builder
    pub const fn new() -> Self {
        NvIndexAttributesBuilder {
            nv_index_attributes: NvIndexAttributes(0),
        }
    }

    /// Creates a new builder from existing `NvIndexAttributes`
    pub const fn with_attributes(nv_index_attributes: NvIndexAttributes) -> Self {
        NvIndexAttributesBuilder {
            nv_index_attributes,
        }
    }

    /// Controls the `pp write` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_pp_write(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_pp_write(set);
        self
    }

    /// Controls the `owner write` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_owner_write(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_owner_write(set);
        self
    }

    /// Controls the `auth write` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_auth_write(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_auth_write(set);
        self
    }

    /// Controls the `policy write` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_policy_write(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_policy_write(set);
        self
    }

    /// Controls the `nv index type` attribute
    ///
    /// # Arguments
    /// * `nv_index_type` - The nv index type to be used.
    pub fn with_nv_index_type(mut self, nv_index_type: NvIndexType) -> Self {
        self.nv_index_attributes.set_index_type(nv_index_type);
        self
    }

    /// Controls the `policy delete` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_policy_delete(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_policy_delete(set);
        self
    }

    /// Controls the `write locked` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_write_locked(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_write_locked(set);
        self
    }

    /// Controls the `write all` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_write_all(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_write_all(set);
        self
    }

    /// Controls the `write define` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_write_define(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_write_define(set);
        self
    }

    /// Controls the `write stclear` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_write_stclear(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_write_stclear(set);
        self
    }

    /// Controls the `global lock` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_global_lock(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_global_lock(set);
        self
    }

    /// Controls the `pp read` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_pp_read(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_pp_read(set);
        self
    }

    /// Controls the `owner read` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_owner_read(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_owner_read(set);
        self
    }

    /// Controls the `auth read` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_auth_read(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_auth_read(set);
        self
    }

    /// Controls the `policy read` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_policy_read(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_policy_read(set);
        self
    }

    /// Controls the `no DA` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_no_da(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_no_da(set);
        self
    }

    /// Controls the `orderly` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_orderly(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_orderly(set);
        self
    }

    /// Controls the `clear stclear` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_clear_stclear(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_clear_stclear(set);
        self
    }

    /// Controls the `read locked` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_read_locked(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_read_locked(set);
        self
    }

    /// Controls the `written` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_written(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_written(set);
        self
    }

    /// Controls the `platform create` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_platform_create(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_platform_create(set);
        self
    }

    /// Controls the `read stclear` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_read_stclear(mut self, set: bool) -> Self {
        self.nv_index_attributes.set_read_stclear(set);
        self
    }

    /// Builds the nv index attributes.
    ///
    /// # Errors
    /// Returns an error if some attributes are missing
    /// or are in conflict with each other.
    pub fn build(self) -> Result<NvIndexAttributes> {
        self.nv_index_attributes.validate()?;
        Ok(self.nv_index_attributes)
    }
}

impl Default for NvIndexAttributesBuilder {
    fn default() -> Self {
        NvIndexAttributesBuilder::new()
    }
}
