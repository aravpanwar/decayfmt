// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::tss2_esys::TPM2B_NAME;
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::TryFrom;
/// Structure holding the data representing names
#[allow(missing_copy_implementations)]
#[derive(Debug, Clone)]
pub struct Name {
    value: TPM2B_NAME,
}

impl Name {
    const MAX_SIZE: usize = 68;
    pub fn value(&self) -> &[u8] {
        &self.value.name[..self.value.size as usize]
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

impl Eq for Name {}

impl TryFrom<Vec<u8>> for Name {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > Name::MAX_SIZE {
            error!("Invalid Vec<u8> size(> {})", Name::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let size = bytes.len() as u16;
        let mut name = [0; Name::MAX_SIZE];
        name[..bytes.len()].copy_from_slice(&bytes);
        Ok(Name {
            value: TPM2B_NAME { size, name },
        })
    }
}

impl TryFrom<TPM2B_NAME> for Name {
    type Error = Error;
    fn try_from(tss_name: TPM2B_NAME) -> Result<Self> {
        let size = tss_name.size as usize;
        if size > Name::MAX_SIZE {
            error!("Invalid TPM2B_NAME size(> {})", Name::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(Name { value: tss_name })
    }
}

impl From<Name> for TPM2B_NAME {
    fn from(name: Name) -> Self {
        name.value
    }
}

impl AsRef<TPM2B_NAME> for Name {
    fn as_ref(&self) -> &TPM2B_NAME {
        &self.value
    }
}
