// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    context::handle_manager::HandleDropAction,
    handles::{AuthHandle, KeyHandle, ObjectHandle},
    interface_types::{resource_handles::Hierarchy, YesNo},
    structures::{
        Auth, CreatePrimaryKeyResult, CreationData, CreationTicket, Data, Digest, PcrSelectionList,
        Public, SensitiveData,
    },
    tss2_esys::{
        Esys_Clear, Esys_ClearControl, Esys_CreatePrimary, Esys_HierarchyChangeAuth,
        TPM2B_SENSITIVE_CREATE, TPMS_SENSITIVE_CREATE,
    },
    Context, Error, Result,
};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
    ptr::null_mut,
};

impl Context {
    /// Create a primary key and return the handle.
    ///
    /// The authentication value, initial data, outside info and creation PCRs are passed as slices
    /// which are then converted by the method into TSS native structures.
    ///
    /// # Errors
    /// * if either of the slices is larger than the maximum size of the native objects, a
    ///   `WrongParamSize` wrapper error is returned
    // TODO: Fix when compacting the arguments into a struct
    #[allow(clippy::too_many_arguments)]
    pub fn create_primary(
        &mut self,
        primary_handle: Hierarchy,
        public: Public,
        auth_value: Option<Auth>,
        initial_data: Option<SensitiveData>,
        outside_info: Option<Data>,
        creation_pcrs: Option<PcrSelectionList>,
    ) -> Result<CreatePrimaryKeyResult> {
        let sensitive_create = TPM2B_SENSITIVE_CREATE {
            size: size_of::<TPMS_SENSITIVE_CREATE>().try_into().unwrap(),
            sensitive: TPMS_SENSITIVE_CREATE {
                userAuth: auth_value.unwrap_or_default().into(),
                data: initial_data.unwrap_or_default().into(),
            },
        };
        let creation_pcrs = PcrSelectionList::list_from_option(creation_pcrs);

        let mut out_public_ptr = null_mut();
        let mut creation_data_ptr = null_mut();
        let mut creation_hash_ptr = null_mut();
        let mut creation_ticket_ptr = null_mut();
        let mut object_handle = ObjectHandle::None.into();

        let ret = unsafe {
            Esys_CreatePrimary(
                self.mut_context(),
                ObjectHandle::from(primary_handle).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &sensitive_create,
                &public.try_into()?,
                &outside_info.unwrap_or_default().into(),
                &creation_pcrs.into(),
                &mut object_handle,
                &mut out_public_ptr,
                &mut creation_data_ptr,
                &mut creation_hash_ptr,
                &mut creation_ticket_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let out_public_owned = Context::ffi_data_to_owned(out_public_ptr);
            let creation_data_owned = Context::ffi_data_to_owned(creation_data_ptr);
            let creation_hash_owned = Context::ffi_data_to_owned(creation_hash_ptr);
            let creation_ticket_owned = Context::ffi_data_to_owned(creation_ticket_ptr);
            let primary_key_handle = KeyHandle::from(object_handle);
            self.handle_manager
                .add_handle(primary_key_handle.into(), HandleDropAction::Flush)?;

            Ok(CreatePrimaryKeyResult {
                key_handle: primary_key_handle,
                out_public: Public::try_from(out_public_owned)?,
                creation_data: CreationData::try_from(creation_data_owned)?,
                creation_hash: Digest::try_from(creation_hash_owned)?,
                creation_ticket: CreationTicket::try_from(creation_ticket_owned)?,
            })
        } else {
            error!("Error in creating primary key: {}", ret);
            Err(ret)
        }
    }

    // Missing function: HierarchyControl
    // Missing function: SetPrimaryPolicy
    // Missing function: ChangePPS
    // Missing function: ChangeEPS

    /// Clear all TPM context associated with a specific Owner
    pub fn clear(&mut self, auth_handle: AuthHandle) -> Result<()> {
        let ret = unsafe {
            Esys_Clear(
                self.mut_context(),
                auth_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            Ok(())
        } else {
            error!("Error in clearing TPM hierarchy: {}", ret);
            Err(ret)
        }
    }

    /// Disable or enable the TPM2_CLEAR command
    pub fn clear_control(&mut self, auth_handle: AuthHandle, disable: bool) -> Result<()> {
        let ret = unsafe {
            Esys_ClearControl(
                self.mut_context(),
                auth_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                YesNo::from(disable).into(),
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            Ok(())
        } else {
            error!("Error in controlling clear command: {}", ret);
            Err(ret)
        }
    }

    /// Change authorization for a hierarchy root
    pub fn hierarchy_change_auth(&mut self, auth_handle: AuthHandle, new_auth: Auth) -> Result<()> {
        let ret = unsafe {
            Esys_HierarchyChangeAuth(
                self.mut_context(),
                auth_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                &new_auth.into(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error changing hierarchy auth: {}", ret);
            Err(ret)
        }
    }
}
