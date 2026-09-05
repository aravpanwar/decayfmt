// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::Attest, traits::UnMarshall, tss2_esys::TPM2B_ATTEST, Error, Result,
    WrapperErrorKind,
};
use log::error;
use std::{convert::TryFrom, ops::Deref};
use zeroize::Zeroizing;

/// Attestation data buffer.
///
/// # Details
/// Corresponds to `TPM2B_ATTEST`. The contents of
/// the buffer can be unmarshalled into an [Attest]
/// structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestBuffer(Zeroizing<Vec<u8>>);

impl Default for AttestBuffer {
    fn default() -> Self {
        AttestBuffer(Vec::new().into())
    }
}

impl AttestBuffer {
    pub const MAX_SIZE: usize = 2304;

    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for AttestBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for AttestBuffer {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > Self::MAX_SIZE {
            error!("Invalid Vec<u8> size(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(AttestBuffer(bytes.into()))
    }
}

impl TryFrom<&[u8]> for AttestBuffer {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_SIZE {
            error!("Invalid &[u8] size(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(AttestBuffer(bytes.to_vec().into()))
    }
}

impl TryFrom<TPM2B_ATTEST> for AttestBuffer {
    type Error = Error;

    fn try_from(tss: TPM2B_ATTEST) -> Result<Self> {
        let size = tss.size as usize;
        if size > Self::MAX_SIZE {
            error!("Invalid buffer size(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(AttestBuffer(tss.attestationData[..size].to_vec().into()))
    }
}

impl From<AttestBuffer> for TPM2B_ATTEST {
    fn from(native: AttestBuffer) -> Self {
        let mut buffer = TPM2B_ATTEST {
            size: native.0.len() as u16,
            ..Default::default()
        };
        buffer.attestationData[..native.0.len()].copy_from_slice(&native.0);
        buffer
    }
}

impl TryFrom<AttestBuffer> for Attest {
    type Error = Error;

    fn try_from(buf: AttestBuffer) -> Result<Self> {
        Attest::unmarshall(&buf.0)
    }
}
