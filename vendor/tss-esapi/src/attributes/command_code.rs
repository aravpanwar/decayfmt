// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::CommandCode,
    tss2_esys::{TPM2_CC, TPMA_CC},
    Error, Result, WrapperErrorKind,
};
use bitfield::bitfield;
use log::error;
use std::convert::{TryFrom, TryInto};

bitfield! {
    /// Bitfield representing the command code attributes.
    ///
    /// # Details
    /// This corresponds to TPMA_CC.
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct CommandCodeAttributes(TPMA_CC);
    impl Debug;
    pub u16, command_index, _: 15, 0;
    u16, _, set_command_index: 15, 0;
    u8, reserved, set_reserved: 21, 16; // shall be zero
    pub nv, _: 22;
    _, set_nv: 22;
    pub extensive, _: 23;
    _, set_extensive: 23;
    pub flushed, _: 24;
    _, set_flushed: 24;
    pub u8, c_handles, _: 27, 25;
    u8, _, set_c_handles: 27, 25;
    pub r_handle, _: 28;
    _, set_r_handle: 28;
    pub is_vendor_specific, _: 29;
    _, set_vendor_specific: 29;
    res, set_res: 31, 30; // shall be zero
}

impl CommandCodeAttributes {
    /// Returns a command code attributes builder
    pub const fn builder() -> CommandCodeAttributesBuilder {
        CommandCodeAttributesBuilder::new()
    }
}

impl TryFrom<TPMA_CC> for CommandCodeAttributes {
    type Error = Error;

    fn try_from(tpma_cc: TPMA_CC) -> Result<Self> {
        let command_code_attributes = CommandCodeAttributes(tpma_cc);
        if command_code_attributes.reserved() != 0 || command_code_attributes.res() != 0 {
            error!(
                "Command code attributes from the TPM contained a non zero value in a resrved area"
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        if !command_code_attributes.is_vendor_specific() {
            // Non vendor specific command code attributes needs to
            // have a command index that corresponds to a command code.
            let tpm_command_code: TPM2_CC = command_code_attributes.command_index().into();
            let _ = CommandCode::try_from(tpm_command_code)?;
        }
        Ok(command_code_attributes)
    }
}

impl From<CommandCodeAttributes> for TPMA_CC {
    fn from(command_code_attributes: CommandCodeAttributes) -> Self {
        command_code_attributes.0
    }
}

/// A builder for [CommandCodeAttributes]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CommandCodeAttributesBuilder {
    command_code_attributes: CommandCodeAttributes,
}

impl CommandCodeAttributesBuilder {
    /// Creates a new command code attributes builder.
    pub const fn new() -> Self {
        CommandCodeAttributesBuilder {
            command_code_attributes: CommandCodeAttributes(0),
        }
    }

    /// Sets the command code to the specified value
    /// in the builder.
    pub fn with_command_index(mut self, command_index: u16) -> Self {
        self.command_code_attributes
            .set_command_index(command_index);
        self
    }

    /// Sets the 'nv' bit in the builder.
    pub fn with_nv(mut self, set: bool) -> Self {
        self.command_code_attributes.set_nv(set);
        self
    }

    /// Sets the 'extensive' bit in the builder.
    pub fn with_extensive(mut self, set: bool) -> Self {
        self.command_code_attributes.set_extensive(set);
        self
    }

    /// Sets the 'flushed' bit in the builder.
    pub fn with_flushed(mut self, set: bool) -> Self {
        self.command_code_attributes.set_flushed(set);
        self
    }

    /// Sets the three 'c_handles' bits in the builder.
    ///
    /// # Details
    /// All bits besides the three first in the provided
    /// argument will be ignored.
    pub fn with_c_handles(mut self, value: u8) -> Self {
        self.command_code_attributes.set_c_handles(value);
        self
    }

    /// Sets the 'r_handle' bit in the builder.
    pub fn with_r_handle(mut self, set: bool) -> Self {
        self.command_code_attributes.set_r_handle(set);
        self
    }

    /// Sets the 'V'(i.e. vendor specific) bit in the builder.
    pub fn with_vendor_specific(mut self, set: bool) -> Self {
        self.command_code_attributes.set_vendor_specific(set);
        self
    }

    /// Builds the command code attributes
    ///
    /// # Errors
    /// Returns an error if command index is not
    /// a command index associated with a CommandCode
    /// specified in the TPM specification.
    pub fn build(self) -> Result<CommandCodeAttributes> {
        self.command_code_attributes.0.try_into()
    }
}

impl Default for CommandCodeAttributesBuilder {
    fn default() -> Self {
        Self::new()
    }
}
