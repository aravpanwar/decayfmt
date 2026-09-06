// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::Public,
    traits::{Marshall, UnMarshall},
    tss2_esys::{TPM2B_PUBLIC, TPMT_PUBLIC},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
    ops::Deref,
};
use zeroize::Zeroize;

/// Public data buffer.
///
/// # Details
/// Corresponds to `TPM2B_PUBLIC`. The contents of
/// the buffer can be unmarshalled into a [Public]
/// structure.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct PublicBuffer(Vec<u8>);

impl PublicBuffer {
    #[allow(unused_qualifications)]
    pub const MAX_SIZE: usize = size_of::<TPMT_PUBLIC>();

    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for PublicBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for PublicBuffer {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > Self::MAX_SIZE {
            error!(
                "Error: Invalid Vec<u8> size ({} > {})",
                bytes.len(),
                Self::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(PublicBuffer(bytes))
    }
}

impl TryFrom<&[u8]> for PublicBuffer {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_SIZE {
            error!(
                "Error: Invalid &[u8] size ({} > {})",
                bytes.len(),
                Self::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(PublicBuffer(bytes.to_vec()))
    }
}

impl TryFrom<TPM2B_PUBLIC> for PublicBuffer {
    type Error = Error;

    fn try_from(tss: TPM2B_PUBLIC) -> Result<Self> {
        let size = tss.size as usize;
        if size > Self::MAX_SIZE {
            error!("Error: Invalid buffer size ({} > {})", size, Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let public = Public::try_from(tss.publicArea)?;
        Ok(PublicBuffer(public.marshall()?))
    }
}

impl TryFrom<PublicBuffer> for TPM2B_PUBLIC {
    type Error = Error;

    fn try_from(native: PublicBuffer) -> Result<Self> {
        let mut buffer = TPM2B_PUBLIC {
            size: native.0.len() as u16,
            ..Default::default()
        };
        let public = Public::unmarshall(&native.0)?;
        buffer.publicArea = public.into();
        Ok(buffer)
    }
}

impl TryFrom<PublicBuffer> for Public {
    type Error = Error;

    fn try_from(buf: PublicBuffer) -> Result<Self> {
        Public::unmarshall(&buf.0)
    }
}

impl TryFrom<Public> for PublicBuffer {
    type Error = Error;

    fn try_from(public: Public) -> Result<PublicBuffer> {
        Ok(PublicBuffer(public.marshall()?))
    }
}

impl Marshall for PublicBuffer {
    const BUFFER_SIZE: usize = size_of::<TPM2B_PUBLIC>();

    /// Produce a marshalled [`TPM2B_PUBLIC`]
    fn marshall(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; Self::BUFFER_SIZE];
        let mut offset = 0;

        let ret = Error::from_tss_rc(unsafe {
            crate::tss2_esys::Tss2_MU_TPM2B_PUBLIC_Marshal(
                &self.clone().try_into()?,
                buffer.as_mut_ptr(),
                Self::BUFFER_SIZE.try_into().map_err(|e| {
                    error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?,
                &mut offset,
            )
        });

        if !ret.is_success() {
            return Err(ret);
        }

        let checked_offset = usize::try_from(offset).map_err(|e| {
            error!("Failed to parse offset as usize: {}", e);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        buffer.truncate(checked_offset);

        Ok(buffer)
    }
}

impl UnMarshall for PublicBuffer {
    /// Unmarshall the structure from [`TPM2B_PUBLIC`]
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self> {
        let mut dest = TPM2B_PUBLIC::default();
        let mut offset = 0;

        let ret = Error::from_tss_rc(unsafe {
            crate::tss2_esys::Tss2_MU_TPM2B_PUBLIC_Unmarshal(
                marshalled_data.as_ptr(),
                marshalled_data.len().try_into().map_err(|e| {
                    error!("Failed to convert length of marshalled data: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?,
                &mut offset,
                &mut dest,
            )
        });

        if !ret.is_success() {
            return Err(ret);
        }

        PublicBuffer::try_from(dest)
    }
}
