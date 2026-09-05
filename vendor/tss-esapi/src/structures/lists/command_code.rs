// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::CommandCode,
    tss2_esys::{TPM2_MAX_CAP_CC, TPML_CC},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{convert::TryFrom, ops::Deref};

/// A list of command codes.
#[derive(Debug, Clone, Default)]
pub struct CommandCodeList {
    command_codes: Vec<CommandCode>,
}

impl CommandCodeList {
    pub const MAX_SIZE: usize = Self::calculate_max_size();
    /// Creates a new CommandCodeList
    pub const fn new() -> Self {
        CommandCodeList {
            command_codes: Vec::new(),
        }
    }

    /// Adds a command code to the command code list.
    pub fn add(&mut self, command_code: CommandCode) -> Result<()> {
        if self.command_codes.len() + 1 > CommandCodeList::MAX_SIZE {
            error!(
                "Adding command code to list will make the list exceeded its maximum count(> {})",
                CommandCodeList::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        self.command_codes.push(command_code);
        Ok(())
    }

    /// Returns the inner type.
    pub fn into_inner(self) -> Vec<CommandCode> {
        self.command_codes
    }

    /// Private function that calculates the maximum number
    /// elements allowed in internal storage.
    const fn calculate_max_size() -> usize {
        TPM2_MAX_CAP_CC as usize
    }
}

impl TryFrom<TPML_CC> for CommandCodeList {
    type Error = Error;

    fn try_from(tpml_cc: TPML_CC) -> Result<Self> {
        let command_code_count = tpml_cc.count as usize;
        if command_code_count > Self::MAX_SIZE {
            error!("Error: Invalid TPML_CC count(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        tpml_cc.commandCodes[..command_code_count]
            .iter()
            .map(|&cc| CommandCode::try_from(cc))
            .collect::<Result<Vec<CommandCode>>>()
            .map(|command_codes| CommandCodeList { command_codes })
    }
}

impl From<CommandCodeList> for TPML_CC {
    fn from(command_code_list: CommandCodeList) -> Self {
        let mut tpml_cc = TPML_CC::default();
        for cc in command_code_list.command_codes {
            tpml_cc.commandCodes[tpml_cc.count as usize] = cc.into();
            tpml_cc.count += 1;
        }
        tpml_cc
    }
}

impl TryFrom<Vec<CommandCode>> for CommandCodeList {
    type Error = Error;

    fn try_from(command_codes: Vec<CommandCode>) -> Result<Self> {
        if command_codes.len() > Self::MAX_SIZE {
            error!("Error: Invalid TPML_CC count(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(CommandCodeList { command_codes })
    }
}

impl From<CommandCodeList> for Vec<CommandCode> {
    fn from(command_code_list: CommandCodeList) -> Self {
        command_code_list.command_codes
    }
}

impl AsRef<[CommandCode]> for CommandCodeList {
    fn as_ref(&self) -> &[CommandCode] {
        self.command_codes.as_slice()
    }
}

impl Deref for CommandCodeList {
    type Target = Vec<CommandCode>;

    fn deref(&self) -> &Self::Target {
        &self.command_codes
    }
}
