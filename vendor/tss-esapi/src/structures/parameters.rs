// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::SymmetricDefinitionObject, tss2_esys::TPMS_SYMCIPHER_PARMS, Error, Result,
};

use std::convert::{TryFrom, TryInto};

/// Symmetric cipher parameters
///
/// # Details
/// Corresponds to TPMS_SYMCIPHER_PARMS
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct SymmetricCipherParameters {
    symmetric_definition_object: SymmetricDefinitionObject,
}

impl SymmetricCipherParameters {
    /// Creates a new [SymmetricDefinitionObject]
    pub const fn new(
        symmetric_definition_object: SymmetricDefinitionObject,
    ) -> SymmetricCipherParameters {
        SymmetricCipherParameters {
            symmetric_definition_object,
        }
    }

    /// Returns the [SymmetricDefinitionObject].
    pub const fn symmetric_definition_object(&self) -> SymmetricDefinitionObject {
        self.symmetric_definition_object
    }
}

impl TryFrom<TPMS_SYMCIPHER_PARMS> for SymmetricCipherParameters {
    type Error = Error;
    fn try_from(tpms_symcipher_params: TPMS_SYMCIPHER_PARMS) -> Result<SymmetricCipherParameters> {
        Ok(SymmetricCipherParameters {
            symmetric_definition_object: tpms_symcipher_params.sym.try_into()?,
        })
    }
}

impl From<SymmetricCipherParameters> for TPMS_SYMCIPHER_PARMS {
    fn from(symmetric_cipher_parameters: SymmetricCipherParameters) -> TPMS_SYMCIPHER_PARMS {
        TPMS_SYMCIPHER_PARMS {
            sym: symmetric_cipher_parameters
                .symmetric_definition_object
                .into(),
        }
    }
}
