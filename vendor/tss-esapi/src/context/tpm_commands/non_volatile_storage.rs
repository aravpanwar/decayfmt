// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    context::handle_manager::HandleDropAction,
    handles::{AuthHandle, NvIndexHandle, ObjectHandle},
    interface_types::resource_handles::{NvAuth, Provision},
    structures::{Auth, MaxNvBuffer, Name, NvPublic},
    tss2_esys::{
        Esys_NV_DefineSpace, Esys_NV_Increment, Esys_NV_Read, Esys_NV_ReadPublic,
        Esys_NV_UndefineSpace, Esys_NV_Write,
    },
    Context, Error, Result,
};
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Allocates an index in the non volatile storage.
    ///
    /// # Details
    /// This method will instruct the TPM to reserve space for an NV index
    /// with the attributes defined in the provided parameters.
    ///
    /// # Arguments
    /// * `nv_auth` - The [Provision] used for authorization.
    /// * `auth` - The authorization value.
    /// * `public_info` - The public parameters of the NV area.
    pub fn nv_define_space(
        &mut self,
        nv_auth: Provision,
        auth: Option<Auth>,
        public_info: NvPublic,
    ) -> Result<NvIndexHandle> {
        let mut nv_handle = ObjectHandle::None.into();
        let ret = unsafe {
            Esys_NV_DefineSpace(
                self.mut_context(),
                AuthHandle::from(nv_auth).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &auth.unwrap_or_default().into(),
                &public_info.try_into()?,
                &mut nv_handle,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            self.handle_manager
                .add_handle(nv_handle.into(), HandleDropAction::Close)?;
            Ok(NvIndexHandle::from(nv_handle))
        } else {
            error!("Error when defining NV space: {}", ret);
            Err(ret)
        }
    }

    /// Deletes an index in the non volatile storage.
    ///
    /// # Details
    /// The method will instruct the TPM to remove a
    /// nv index.
    ///
    /// # Arguments
    /// * `nv_auth` - The [Provision] used for authorization.
    /// * `nv_index_handle`- The [NvIndexHandle] associated with
    ///   the nv area that is to be removed.
    pub fn nv_undefine_space(
        &mut self,
        nv_auth: Provision,
        nv_index_handle: NvIndexHandle,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_NV_UndefineSpace(
                self.mut_context(),
                AuthHandle::from(nv_auth).into(),
                nv_index_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
            )
        };

        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            self.handle_manager.set_as_closed(nv_index_handle.into())?;
            Ok(())
        } else {
            error!("Error when undefining NV space: {}", ret);
            Err(ret)
        }
    }

    // Missing function: UndefineSpaceSpecial

    /// Reads the public part of an nv index.
    ///
    /// # Details
    /// This method is used to read the public
    /// area and name of a nv index.
    pub fn nv_read_public(&mut self, nv_index_handle: NvIndexHandle) -> Result<(NvPublic, Name)> {
        let mut nv_public_ptr = null_mut();
        let mut nv_name_ptr = null_mut();
        let ret = unsafe {
            Esys_NV_ReadPublic(
                self.mut_context(),
                nv_index_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &mut nv_public_ptr,
                &mut nv_name_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok((
                NvPublic::try_from(Context::ffi_data_to_owned(nv_public_ptr))?,
                Name::try_from(Context::ffi_data_to_owned(nv_name_ptr))?,
            ))
        } else {
            error!("Error when reading NV public: {}", ret);
            Err(ret)
        }
    }

    /// Writes data to an nv index.
    ///
    /// # Details
    /// This method is used to write a value to
    /// the nv memory in the TPM.
    pub fn nv_write(
        &mut self,
        auth_handle: NvAuth,
        nv_index_handle: NvIndexHandle,
        data: MaxNvBuffer,
        offset: u16,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_NV_Write(
                self.mut_context(),
                AuthHandle::from(auth_handle).into(),
                nv_index_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &data.into(),
                offset,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when writing NV: {}", ret);
            Err(ret)
        }
    }

    /// Increment monotonic counter index
    ///
    /// # Details
    /// This method is used to increment monotonic counter
    /// in the TPM.
    pub fn nv_increment(
        &mut self,
        auth_handle: NvAuth,
        nv_index_handle: NvIndexHandle,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_NV_Increment(
                self.mut_context(),
                AuthHandle::from(auth_handle).into(),
                nv_index_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when incrementing NV: {}", ret);
            Err(ret)
        }
    }

    // Missing function: NV_Extend
    // Missing function: NV_SetBits
    // Missing function: NV_WriteLock
    // Missing function: NV_GlobalWriteLock

    /// Reads data from the nv index.
    ///
    /// # Details
    /// This method is used to read a value from an area in
    /// NV memory of the TPM.
    pub fn nv_read(
        &mut self,
        auth_handle: NvAuth,
        nv_index_handle: NvIndexHandle,
        size: u16,
        offset: u16,
    ) -> Result<MaxNvBuffer> {
        let mut data_ptr = null_mut();
        let ret = unsafe {
            Esys_NV_Read(
                self.mut_context(),
                AuthHandle::from(auth_handle).into(),
                nv_index_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                size,
                offset,
                &mut data_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            MaxNvBuffer::try_from(Context::ffi_data_to_owned(data_ptr))
        } else {
            error!("Error when reading NV: {}", ret);
            Err(ret)
        }
    }

    // Missing function: NV_ReadLock
    // Missing function: NV_ChangeAuth
    // Missing function: NV_Certify
}
