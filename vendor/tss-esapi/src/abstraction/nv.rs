// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::{
    convert::{TryFrom, TryInto},
    io::Read,
};

use crate::{
    constants::{tss::*, CapabilityType, PropertyTag},
    handles::{AuthHandle, NvIndexHandle, NvIndexTpmHandle, TpmHandle},
    interface_types::resource_handles::NvAuth,
    structures::{CapabilityData, MaxNvBuffer, Name, NvPublic},
    Context, Error, Result, WrapperErrorKind,
};

/// Allows reading an NV Index completely, regardless of the max TPM NV buffer size
pub fn read_full(
    context: &mut Context,
    auth_handle: NvAuth,
    nv_index_handle: NvIndexTpmHandle,
) -> Result<Vec<u8>> {
    let mut rw = NvOpenOptions::ExistingIndex {
        auth_handle,
        nv_index_handle,
    }
    .open(context)?;
    let mut result = Vec::with_capacity(rw.size());

    let _ = rw.read_to_end(&mut result).map_err(|e| {
        // Try to convert the error back into a tss-esapi::Error if it was one originally
        match e.into_inner() {
            None => Error::WrapperError(WrapperErrorKind::InvalidParam),
            Some(e) => match e.downcast::<Error>() {
                Ok(e) => *e,
                Err(_) => Error::WrapperError(WrapperErrorKind::InvalidParam),
            },
        }
    })?;

    Ok(result)
}

/// Returns the NvPublic and Name associated with an NV index TPM handle
///
/// NOTE: This call _may_ close existing ESYS handles to the NV Index.
fn get_nv_index_info(
    context: &mut Context,
    nv_index_tpm_handle: NvIndexTpmHandle,
) -> Result<(NvPublic, Name)> {
    context
        .tr_from_tpm_public(nv_index_tpm_handle.into())
        .and_then(|mut object_handle| {
            context
                .nv_read_public(NvIndexHandle::from(object_handle))
                .inspect_err(|_| {
                    let _ = context.tr_close(&mut object_handle);
                })
                .and_then(|(nv_public, name)| {
                    context.tr_close(&mut object_handle)?;
                    Ok((nv_public, name))
                })
        })
}

/// Lists all the currently defined NV Indexes' names and public components
///
/// NOTE: This call _may_ close existing ESYS handles to the existing NV Indexes.
pub fn list(context: &mut Context) -> Result<Vec<(NvPublic, Name)>> {
    context.execute_without_session(|ctx| {
        ctx.get_capability(
            CapabilityType::Handles,
            TPM2_NV_INDEX_FIRST,
            TPM2_PT_NV_INDEX_MAX,
        )
        .and_then(|(capability_data, _)| match capability_data {
            CapabilityData::Handles(tpm_handles) => Ok(tpm_handles),
            _ => Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm)),
        })
        .and_then(|tpm_handles| {
            tpm_handles
                .iter()
                .map(|&tpm_handle| get_nv_index_info(ctx, NvIndexTpmHandle::try_from(tpm_handle)?))
                .collect()
        })
    })
}

/// Options and flags which can be used to determine how a non-volatile storage index is opened.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum NvOpenOptions {
    /// Define a new NV space with given auth
    NewIndex {
        nv_public: NvPublic,
        auth_handle: NvAuth,
    },
    /// Open the NV space at the given handle, with the given auth
    ExistingIndex {
        nv_index_handle: NvIndexTpmHandle,
        auth_handle: NvAuth,
    },
}

impl NvOpenOptions {
    /// Opens a non-volatile storage index using the options specified by `self`
    ///
    /// The non-volatile storage index may be used for reading or writing or both.
    pub fn open<'a>(&self, context: &'a mut Context) -> Result<NvReaderWriter<'a>> {
        let buffer_size = max_nv_buffer_size(context)?;

        let (data_size, nv_idx, auth_handle) = match self {
            NvOpenOptions::ExistingIndex {
                nv_index_handle,
                auth_handle,
            } => {
                let nv_idx = TpmHandle::NvIndex(*nv_index_handle);
                let nv_idx = context
                    .execute_without_session(|ctx| ctx.tr_from_tpm_public(nv_idx))?
                    .into();
                (
                    context
                        .execute_without_session(|ctx| ctx.nv_read_public(nv_idx))
                        .map(|(nvpub, _)| nvpub.data_size())?,
                    nv_idx,
                    auth_handle,
                )
            }
            NvOpenOptions::NewIndex {
                nv_public,
                auth_handle,
            } => (
                nv_public.data_size(),
                context.nv_define_space(
                    AuthHandle::from(*auth_handle).try_into()?,
                    None,
                    nv_public.clone(),
                )?,
                auth_handle,
            ),
        };

        Ok(NvReaderWriter {
            context,
            auth_handle: *auth_handle,
            buffer_size,
            nv_idx,
            data_size,
            offset: 0,
        })
    }
}

/// Get the maximum buffer size for an NV space.
pub fn max_nv_buffer_size(ctx: &mut Context) -> Result<usize> {
    Ok(ctx
        .get_tpm_property(PropertyTag::NvBufferMax)?
        .map(usize::try_from)
        .transpose()
        .map_err(|_| {
            log::error!("Failed to obtain valid maximum NV buffer size");
            Error::WrapperError(WrapperErrorKind::InternalError)
        })?
        .unwrap_or(MaxNvBuffer::MAX_SIZE))
}

/// Non-volatile storage index reader/writer
///
/// Provides methods and trait implementations to interact with a non-volatile storage index that has been opened.
///
/// Use [`NvOpenOptions::open`] to obtain an [`NvReaderWriter`] object.
///
/// NOTE: When the `NvReaderWriter` is dropped, any existing ESYS handles to NV Indexes _may_ be closed.
#[derive(Debug)]
pub struct NvReaderWriter<'a> {
    context: &'a mut Context,
    auth_handle: NvAuth,

    buffer_size: usize,
    nv_idx: NvIndexHandle,
    data_size: usize,
    offset: usize,
}

impl NvReaderWriter<'_> {
    /// The size of the data in the non-volatile storage index
    pub fn size(&self) -> usize {
        self.data_size
    }
}

impl Read for NvReaderWriter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.data_size <= self.offset {
            return Ok(0);
        }

        let desired_size = std::cmp::min(buf.len(), self.data_size - self.offset);
        let size: u16 = std::cmp::min(self.buffer_size, desired_size) as u16;

        let res = self
            .context
            .nv_read(self.auth_handle, self.nv_idx, size, self.offset as u16)
            .map_err(std::io::Error::other)?;
        buf[0..size as usize].copy_from_slice(&res);
        self.offset += size as usize;

        Ok(size.into())
    }
}

impl std::io::Write for NvReaderWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.data_size < self.offset {
            return Ok(0);
        }

        let desired_size = std::cmp::min(buf.len(), self.data_size - self.offset);
        let size = std::cmp::min(self.buffer_size, desired_size) as u16;

        let data = buf[0..size.into()]
            .try_into()
            .map_err(std::io::Error::other)?;
        self.context
            .nv_write(self.auth_handle, self.nv_idx, data, self.offset as u16)
            .map_err(std::io::Error::other)?;
        self.offset += size as usize;

        Ok(size.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Data isn't buffered
        Ok(())
    }
}

impl std::io::Seek for NvReaderWriter<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let inv_input_err = |_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            )
        };
        let (base, offset) = match pos {
            std::io::SeekFrom::Start(offset) => {
                (usize::try_from(offset).map_err(inv_input_err)?, 0)
            }
            std::io::SeekFrom::End(offset) => (self.data_size, offset),
            std::io::SeekFrom::Current(offset) => (self.offset, offset),
        };
        let new_offset = i64::try_from(base)
            .map_err(inv_input_err)?
            .checked_add(offset)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid seek to a negative or overflowing position",
                )
            })?;
        self.offset = new_offset.try_into().map_err(inv_input_err)?;
        self.offset.try_into().map_err(inv_input_err)
    }
}

impl Drop for NvReaderWriter<'_> {
    fn drop(&mut self) {
        let mut obj_handle = self.nv_idx.into();
        let _ = self
            .context
            .execute_without_session(|ctx| ctx.tr_close(&mut obj_handle));
    }
}
