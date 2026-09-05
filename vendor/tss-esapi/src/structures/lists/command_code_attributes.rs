// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    attributes::CommandCodeAttributes,
    tss2_esys::{TPMA_CC, TPML_CCA},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{convert::TryFrom, iter::IntoIterator, ops::Deref};

/// A structure holding a list of command code attributes.
///
/// # Details
/// This corresponds to the TPML_CCA strucutre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandCodeAttributesList {
    command_code_attributes: Vec<CommandCodeAttributes>,
}

impl CommandCodeAttributesList {
    pub const MAX_SIZE: usize = Self::calculate_max_size();

    /// Finds a command code attributes with a specific
    /// command index
    pub fn find(&self, command_index: u16) -> Option<&CommandCodeAttributes> {
        self.command_code_attributes
            .iter()
            .find(|cca| cca.command_index() == command_index)
    }

    /// Private function that calculates the maximum number
    /// elements allowed in internal storage.
    const fn calculate_max_size() -> usize {
        crate::structures::capability_data::max_cap_size::<TPMA_CC>()
    }
}

impl Deref for CommandCodeAttributesList {
    type Target = Vec<CommandCodeAttributes>;

    fn deref(&self) -> &Self::Target {
        &self.command_code_attributes
    }
}

impl AsRef<[CommandCodeAttributes]> for CommandCodeAttributesList {
    fn as_ref(&self) -> &[CommandCodeAttributes] {
        self.command_code_attributes.as_slice()
    }
}

impl TryFrom<Vec<CommandCodeAttributes>> for CommandCodeAttributesList {
    type Error = Error;

    fn try_from(command_code_attributes: Vec<CommandCodeAttributes>) -> Result<Self> {
        if command_code_attributes.len() > Self::MAX_SIZE {
            error!("Failed to convert Vec<CommandCodeAttributes> into CommandCodeAttributesList, to many items (> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(CommandCodeAttributesList {
            command_code_attributes,
        })
    }
}

impl IntoIterator for CommandCodeAttributesList {
    type Item = CommandCodeAttributes;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.command_code_attributes.into_iter()
    }
}

impl TryFrom<TPML_CCA> for CommandCodeAttributesList {
    type Error = Error;

    fn try_from(tpml_cca: TPML_CCA) -> Result<Self> {
        let count = usize::try_from(tpml_cca.count).map_err(|e| {
            error!("Failed to parse count in TPML_CCA as usize: {}", e);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        if count > Self::MAX_SIZE {
            error!("Invalid size value in TPML_CCA (> {})", Self::MAX_SIZE,);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        tpml_cca.commandAttributes[..count]
            .iter()
            .map(|&tp| CommandCodeAttributes::try_from(tp))
            .collect::<Result<Vec<CommandCodeAttributes>>>()
            .map(|command_code_attributes| CommandCodeAttributesList {
                command_code_attributes,
            })
    }
}

impl From<CommandCodeAttributesList> for TPML_CCA {
    fn from(command_code_attributes_list: CommandCodeAttributesList) -> Self {
        let mut tpml_cca: TPML_CCA = Default::default();
        for command_code_attributes in command_code_attributes_list {
            tpml_cca.commandAttributes[tpml_cca.count as usize] = command_code_attributes.into();
            tpml_cca.count += 1;
        }
        tpml_cca
    }
}
