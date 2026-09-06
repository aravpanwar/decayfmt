// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{
        TPM2_HT_AC, TPM2_HT_HMAC_SESSION, TPM2_HT_NV_INDEX, TPM2_HT_PCR, TPM2_HT_PERMANENT,
        TPM2_HT_PERSISTENT, TPM2_HT_POLICY_SESSION, TPM2_HT_TRANSIENT,
    },
    tss2_esys::TPM2_HANDLE,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{From, TryFrom};
use std::stringify;

/// Enum representing the different types of tpm handles
/// of a TPM handle.
///
/// # Details
/// The TPM handles are used
/// to reference shielded locations of various
/// types within the TPM.
///
/// N.B:
/// Do not confuse the TpmHandles with the
/// ESYS [ObjectHandle](crate::handles::ObjectHandle).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TpmHandle {
    Pcr(pcr::PcrTpmHandle),
    NvIndex(nv_index::NvIndexTpmHandle),
    HmacSession(hmac_session::HmacSessionTpmHandle),
    LoadedSession(loaded_session::LoadedSessionTpmHandle),
    PolicySession(policy_session::PolicySessionTpmHandle),
    SavedSession(saved_session::SavedSessionTpmHandle),
    Permanent(permanent::PermanentTpmHandle),
    Transient(transient::TransientTpmHandle),
    Persistent(persistent::PersistentTpmHandle),
    AttachedComponent(attached_component::AttachedComponentTpmHandle),
}

impl TpmHandle {
    /// Method that indicates if the flushing the
    /// context of the handle is a valid action.
    pub(crate) fn may_be_flushed(&self) -> bool {
        matches!(
            self,
            TpmHandle::HmacSession(_) | TpmHandle::LoadedSession(_) | TpmHandle::Transient(_)
        )
    }
}

impl From<TpmHandle> for TPM2_HANDLE {
    fn from(tpm_handle: TpmHandle) -> TPM2_HANDLE {
        match tpm_handle {
            TpmHandle::Pcr(handle) => handle.into(),
            TpmHandle::NvIndex(handle) => handle.into(),
            TpmHandle::HmacSession(handle) => handle.into(),
            TpmHandle::LoadedSession(handle) => handle.into(),
            TpmHandle::PolicySession(handle) => handle.into(),
            TpmHandle::SavedSession(handle) => handle.into(),
            TpmHandle::Permanent(handle) => handle.into(),
            TpmHandle::Transient(handle) => handle.into(),
            TpmHandle::Persistent(handle) => handle.into(),
            TpmHandle::AttachedComponent(handle) => handle.into(),
        }
    }
}

impl TryFrom<TPM2_HANDLE> for TpmHandle {
    type Error = Error;
    fn try_from(tss_tpm_handle: TPM2_HANDLE) -> Result<TpmHandle> {
        let most_significant_byte = tss_tpm_handle.to_be_bytes()[0];
        match most_significant_byte {
            TPM2_HT_PCR => Ok(TpmHandle::Pcr(pcr::PcrTpmHandle::new(tss_tpm_handle)?)),
            TPM2_HT_NV_INDEX => Ok(TpmHandle::NvIndex(nv_index::NvIndexTpmHandle::new(
                tss_tpm_handle,
            )?)),
            TPM2_HT_HMAC_SESSION => Ok(TpmHandle::HmacSession(
                hmac_session::HmacSessionTpmHandle::new(tss_tpm_handle)?,
            )),
            // HMAC and LOADED has the same type id
            TPM2_HT_POLICY_SESSION => Ok(TpmHandle::PolicySession(
                policy_session::PolicySessionTpmHandle::new(tss_tpm_handle)?,
            )),
            // POLICY and SAVED has the same type id.
            TPM2_HT_PERMANENT => Ok(TpmHandle::Permanent(permanent::PermanentTpmHandle::new(
                tss_tpm_handle,
            )?)),
            TPM2_HT_TRANSIENT => Ok(TpmHandle::Transient(transient::TransientTpmHandle::new(
                tss_tpm_handle,
            )?)),
            TPM2_HT_PERSISTENT => Ok(TpmHandle::Persistent(persistent::PersistentTpmHandle::new(
                tss_tpm_handle,
            )?)),
            TPM2_HT_AC => Ok(TpmHandle::AttachedComponent(
                attached_component::AttachedComponentTpmHandle::new(tss_tpm_handle)?,
            )),
            _ => {
                error!("Invalid TPM handle type {}", most_significant_byte);
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}

/// Macro for creating the specific TPM handle types
macro_rules! create_tpm_handle_type {
    ($handle_type_name:ident, $tpm_handle_kind:path, $tpm_handle_type_id:tt, $tpm_handle_type_first:tt, $tpm_handle_type_last:tt) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct $handle_type_name {
            value: u32,
        }

        impl $handle_type_name {
            pub fn new(value: u32) -> Result<$handle_type_name> {
                if value.to_be_bytes()[0] != $tpm_handle_type_id {
                    error!(
                        "TPM Handle ID of the input value did not match the {} (!={})",
                        stringify!($handle_type_name),
                        $tpm_handle_type_id
                    );
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }
                // Add +1 to include tpm_handle_type_last in the range
                if !($tpm_handle_type_first..($tpm_handle_type_last + 1)).contains(&value) {
                    error!(
                        "TPM Handle ID is not in range ({}..{})",
                        $tpm_handle_type_first, $tpm_handle_type_last
                    );
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }
                Ok($handle_type_name { value })
            }
        }

        impl From<$handle_type_name> for TpmHandle {
            fn from(specific_tpm_handle: $handle_type_name) -> TpmHandle {
                $tpm_handle_kind(specific_tpm_handle)
            }
        }

        impl TryFrom<TpmHandle> for $handle_type_name {
            type Error = Error;
            fn try_from(general_tpm_handle: TpmHandle) -> Result<$handle_type_name> {
                match general_tpm_handle {
                    $tpm_handle_kind(val) => Ok(val),
                    _ => {
                        error!(
                            "Error: Incorrect tpm handle kind(=={}) when converting to {}",
                            stringify!($tpm_handle_kind),
                            stringify!($handle_type_name)
                        );
                        return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                    }
                }
            }
        }

        impl From<$handle_type_name> for TPM2_HANDLE {
            fn from(specific_tpm_handle: $handle_type_name) -> TPM2_HANDLE {
                specific_tpm_handle.value
            }
        }

        impl TryFrom<TPM2_HANDLE> for $handle_type_name {
            type Error = Error;
            fn try_from(tss_tpm_handle: TPM2_HANDLE) -> Result<$handle_type_name> {
                $handle_type_name::new(tss_tpm_handle)
            }
        }
    };
}

/// Macro for making a constant available
/// for a TPM handle type.
macro_rules! add_constant_handle {
    ($handle_type:ident, $constant_handle_name:ident, $constant_handle_value:ident) => {
        impl $handle_type {
            #[allow(non_upper_case_globals)]
            pub const $constant_handle_name: $handle_type = $handle_type {
                value: $constant_handle_value,
            };
        }
    };
}

pub mod pcr {
    //! Module for the PCR TPM handle.
    use super::*;
    use crate::constants::tss::{TPM2_HT_PCR, TPM2_PCR_FIRST, TPM2_PCR_LAST};
    // Creates the specific handle types
    create_tpm_handle_type!(
        PcrTpmHandle,
        TpmHandle::Pcr,
        TPM2_HT_PCR,
        TPM2_PCR_FIRST,
        TPM2_PCR_LAST
    );
}

pub mod nv_index {
    //! Module for the NV index TPM handle.
    use super::*;
    use crate::constants::tss::{TPM2_HT_NV_INDEX, TPM2_NV_INDEX_FIRST, TPM2_NV_INDEX_LAST};

    create_tpm_handle_type!(
        NvIndexTpmHandle,
        TpmHandle::NvIndex,
        TPM2_HT_NV_INDEX,
        TPM2_NV_INDEX_FIRST,
        TPM2_NV_INDEX_LAST
    );
}

pub mod hmac_session {
    //! Module for the HMAC session TPM handle.
    use super::*;
    use crate::constants::tss::{
        TPM2_HMAC_SESSION_FIRST, TPM2_HMAC_SESSION_LAST, TPM2_HT_HMAC_SESSION,
    };

    create_tpm_handle_type!(
        HmacSessionTpmHandle,
        TpmHandle::HmacSession,
        TPM2_HT_HMAC_SESSION,
        TPM2_HMAC_SESSION_FIRST,
        TPM2_HMAC_SESSION_LAST
    );
}

pub mod loaded_session {
    //! Module for the loaded session TPM handle.
    use super::*;
    use crate::constants::tss::{
        TPM2_HT_LOADED_SESSION, TPM2_LOADED_SESSION_FIRST, TPM2_LOADED_SESSION_LAST,
    };

    create_tpm_handle_type!(
        LoadedSessionTpmHandle,
        TpmHandle::LoadedSession,
        TPM2_HT_LOADED_SESSION,
        TPM2_LOADED_SESSION_FIRST,
        TPM2_LOADED_SESSION_LAST
    );
}

pub mod policy_session {
    //! Module for policy session TPM handles.
    use super::*;
    use crate::constants::tss::{
        TPM2_HT_POLICY_SESSION, TPM2_POLICY_SESSION_FIRST, TPM2_POLICY_SESSION_LAST,
    };

    create_tpm_handle_type!(
        PolicySessionTpmHandle,
        TpmHandle::PolicySession,
        TPM2_HT_POLICY_SESSION,
        TPM2_POLICY_SESSION_FIRST,
        TPM2_POLICY_SESSION_LAST
    );
}

pub mod permanent {
    use super::*;
    use crate::constants::tss::{
        TPM2_HT_PERMANENT, TPM2_PERMANENT_FIRST, TPM2_PERMANENT_LAST, TPM2_RH_ACT_0, TPM2_RH_ACT_F,
        TPM2_RH_ADMIN, TPM2_RH_AUTH_00, TPM2_RH_AUTH_FF, TPM2_RH_EK, TPM2_RH_ENDORSEMENT,
        TPM2_RH_FIRST, TPM2_RH_LAST, TPM2_RH_LOCKOUT, TPM2_RH_NULL, TPM2_RH_OPERATOR,
        TPM2_RH_OWNER, TPM2_RH_PLATFORM, TPM2_RH_PLATFORM_NV, TPM2_RH_REVOKE, TPM2_RH_SRK,
        TPM2_RH_TRANSPORT, TPM2_RH_UNASSIGNED, TPM2_RS_PW,
    };

    create_tpm_handle_type!(
        PermanentTpmHandle,
        TpmHandle::Permanent,
        TPM2_HT_PERMANENT,
        TPM2_PERMANENT_FIRST,
        TPM2_PERMANENT_LAST
    );

    add_constant_handle!(PermanentTpmHandle, First, TPM2_RH_FIRST);
    add_constant_handle!(PermanentTpmHandle, StorageRootKey, TPM2_RH_SRK);
    add_constant_handle!(PermanentTpmHandle, Owner, TPM2_RH_OWNER);
    add_constant_handle!(PermanentTpmHandle, Revoke, TPM2_RH_REVOKE);
    add_constant_handle!(PermanentTpmHandle, Transport, TPM2_RH_TRANSPORT);
    add_constant_handle!(PermanentTpmHandle, Operator, TPM2_RH_OPERATOR);
    add_constant_handle!(PermanentTpmHandle, Admin, TPM2_RH_ADMIN);
    add_constant_handle!(PermanentTpmHandle, EndorsementKey, TPM2_RH_EK);
    add_constant_handle!(PermanentTpmHandle, Null, TPM2_RH_NULL);
    add_constant_handle!(PermanentTpmHandle, Unassigned, TPM2_RH_UNASSIGNED);
    add_constant_handle!(PermanentTpmHandle, PasswordSession, TPM2_RS_PW);
    add_constant_handle!(PermanentTpmHandle, Lockout, TPM2_RH_LOCKOUT);
    add_constant_handle!(PermanentTpmHandle, Endorsement, TPM2_RH_ENDORSEMENT);
    add_constant_handle!(PermanentTpmHandle, Platform, TPM2_RH_PLATFORM);
    add_constant_handle!(PermanentTpmHandle, PlatformNv, TPM2_RH_PLATFORM_NV);
    add_constant_handle!(
        PermanentTpmHandle,
        VendorSpecificAuthorizationFirst,
        TPM2_RH_AUTH_00
    );
    add_constant_handle!(
        PermanentTpmHandle,
        VendorSpecificAuthorizationLast,
        TPM2_RH_AUTH_FF
    );
    add_constant_handle!(PermanentTpmHandle, AuthenticatedTimersFirst, TPM2_RH_ACT_0);
    add_constant_handle!(PermanentTpmHandle, AuthenticatedTimersLast, TPM2_RH_ACT_F);
    add_constant_handle!(PermanentTpmHandle, Last, TPM2_RH_LAST);
}

pub mod saved_session {
    //! Module for saved session TPM handles
    use super::*;
    use crate::constants::tss::{
        TPM2_HT_SAVED_SESSION, TPM2_POLICY_SESSION_FIRST, TPM2_POLICY_SESSION_LAST,
    };

    create_tpm_handle_type!(
        SavedSessionTpmHandle,
        TpmHandle::SavedSession,
        TPM2_HT_SAVED_SESSION,
        TPM2_POLICY_SESSION_FIRST, // Policy session have the same type as saved session.
        TPM2_POLICY_SESSION_LAST   // so assuming they have the same valid range makes sense.
    );
}

pub mod transient {
    //! Module for transient TPM handles
    use super::*;
    use crate::constants::tss::{TPM2_HT_TRANSIENT, TPM2_TRANSIENT_FIRST, TPM2_TRANSIENT_LAST};

    create_tpm_handle_type!(
        TransientTpmHandle,
        TpmHandle::Transient,
        TPM2_HT_TRANSIENT,
        TPM2_TRANSIENT_FIRST,
        TPM2_TRANSIENT_LAST
    );
}

pub mod persistent {
    //! Module for persistent TPM handles
    use super::*;
    use crate::constants::tss::{TPM2_HT_PERSISTENT, TPM2_PERSISTENT_FIRST, TPM2_PERSISTENT_LAST};

    create_tpm_handle_type!(
        PersistentTpmHandle,
        TpmHandle::Persistent,
        TPM2_HT_PERSISTENT,
        TPM2_PERSISTENT_FIRST,
        TPM2_PERSISTENT_LAST
    );
}

pub mod attached_component {
    //! Module for attached component TPM handles.
    use super::*;
    use crate::constants::tss::{TPM2_AC_FIRST, TPM2_AC_LAST, TPM2_HT_AC};

    create_tpm_handle_type!(
        AttachedComponentTpmHandle,
        TpmHandle::AttachedComponent,
        TPM2_HT_AC,
        TPM2_AC_FIRST,
        TPM2_AC_LAST
    );
}
