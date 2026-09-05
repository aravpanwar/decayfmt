// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::{
        AttachedComponentTpmHandle, AuthHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle,
        PermanentTpmHandle, TpmHandle,
    },
    Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
//////////////////////////////////////////////////////////////////////////////////
/// Hierarchy
///
/// Enum describing the object hierarchies in a TPM 2.0.
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hierarchy {
    Owner,
    Platform,
    Endorsement,
    Null,
}

impl From<Hierarchy> for ObjectHandle {
    fn from(hierarchy: Hierarchy) -> ObjectHandle {
        match hierarchy {
            Hierarchy::Owner => ObjectHandle::Owner,
            Hierarchy::Platform => ObjectHandle::Platform,
            Hierarchy::Endorsement => ObjectHandle::Endorsement,
            Hierarchy::Null => ObjectHandle::Null,
        }
    }
}

impl From<Hierarchy> for TpmHandle {
    fn from(hierarchy: Hierarchy) -> TpmHandle {
        match hierarchy {
            Hierarchy::Owner => TpmHandle::Permanent(PermanentTpmHandle::Owner),
            Hierarchy::Platform => TpmHandle::Permanent(PermanentTpmHandle::Platform),
            Hierarchy::Endorsement => TpmHandle::Permanent(PermanentTpmHandle::Endorsement),
            Hierarchy::Null => TpmHandle::Permanent(PermanentTpmHandle::Null),
        }
    }
}

impl TryFrom<ObjectHandle> for Hierarchy {
    type Error = Error;

    fn try_from(object_handle: ObjectHandle) -> Result<Hierarchy> {
        match object_handle {
            ObjectHandle::Owner => Ok(Hierarchy::Owner),
            ObjectHandle::Platform => Ok(Hierarchy::Platform),
            ObjectHandle::Endorsement => Ok(Hierarchy::Endorsement),
            ObjectHandle::Null => Ok(Hierarchy::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl TryFrom<TpmHandle> for Hierarchy {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Hierarchy> {
        match tpm_handle {
            TpmHandle::Permanent(permanent_handle) => match permanent_handle {
                PermanentTpmHandle::Owner => Ok(Hierarchy::Owner),
                PermanentTpmHandle::Platform => Ok(Hierarchy::Platform),
                PermanentTpmHandle::Endorsement => Ok(Hierarchy::Endorsement),
                PermanentTpmHandle::Null => Ok(Hierarchy::Null),
                _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
            },
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////
/// Enables
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enables {
    Owner,
    Platform,
    Endorsement,
    PlatformNv,
    Null,
}

impl From<Enables> for ObjectHandle {
    fn from(enables: Enables) -> ObjectHandle {
        match enables {
            Enables::Owner => ObjectHandle::Owner,
            Enables::Platform => ObjectHandle::Platform,
            Enables::Endorsement => ObjectHandle::Endorsement,
            Enables::PlatformNv => ObjectHandle::PlatformNv,
            Enables::Null => ObjectHandle::Null,
        }
    }
}

impl From<Enables> for TpmHandle {
    fn from(enables: Enables) -> TpmHandle {
        match enables {
            Enables::Owner => TpmHandle::Permanent(PermanentTpmHandle::Owner),
            Enables::Platform => TpmHandle::Permanent(PermanentTpmHandle::Platform),
            Enables::Endorsement => TpmHandle::Permanent(PermanentTpmHandle::Endorsement),
            Enables::PlatformNv => TpmHandle::Permanent(PermanentTpmHandle::PlatformNv),
            Enables::Null => TpmHandle::Permanent(PermanentTpmHandle::Null),
        }
    }
}

impl TryFrom<ObjectHandle> for Enables {
    type Error = Error;

    fn try_from(object_handle: ObjectHandle) -> Result<Enables> {
        match object_handle {
            ObjectHandle::Owner => Ok(Enables::Owner),
            ObjectHandle::Platform => Ok(Enables::Platform),
            ObjectHandle::Endorsement => Ok(Enables::Endorsement),
            ObjectHandle::PlatformNv => Ok(Enables::PlatformNv),
            ObjectHandle::Null => Ok(Enables::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl TryFrom<TpmHandle> for Enables {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Enables> {
        match tpm_handle {
            TpmHandle::Permanent(permanent_handle) => match permanent_handle {
                PermanentTpmHandle::Owner => Ok(Enables::Owner),
                PermanentTpmHandle::Platform => Ok(Enables::Platform),
                PermanentTpmHandle::Endorsement => Ok(Enables::Endorsement),
                PermanentTpmHandle::PlatformNv => Ok(Enables::PlatformNv),
                PermanentTpmHandle::Null => Ok(Enables::Null),
                _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
            },
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////
/// HierarchyAuth
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HierarchyAuth {
    Owner,
    Platform,
    Endorsement,
    Lockout,
}

impl From<HierarchyAuth> for ObjectHandle {
    fn from(hierarchy_auth: HierarchyAuth) -> ObjectHandle {
        match hierarchy_auth {
            HierarchyAuth::Owner => ObjectHandle::Owner,
            HierarchyAuth::Platform => ObjectHandle::Platform,
            HierarchyAuth::Endorsement => ObjectHandle::Endorsement,
            HierarchyAuth::Lockout => ObjectHandle::Lockout,
        }
    }
}

impl From<HierarchyAuth> for TpmHandle {
    fn from(hierarchy_auth: HierarchyAuth) -> TpmHandle {
        match hierarchy_auth {
            HierarchyAuth::Owner => TpmHandle::Permanent(PermanentTpmHandle::Owner),
            HierarchyAuth::Platform => TpmHandle::Permanent(PermanentTpmHandle::Platform),
            HierarchyAuth::Endorsement => TpmHandle::Permanent(PermanentTpmHandle::Endorsement),
            HierarchyAuth::Lockout => TpmHandle::Permanent(PermanentTpmHandle::Lockout),
        }
    }
}

impl TryFrom<ObjectHandle> for HierarchyAuth {
    type Error = Error;

    fn try_from(object_handle: ObjectHandle) -> Result<HierarchyAuth> {
        match object_handle {
            ObjectHandle::Owner => Ok(HierarchyAuth::Owner),
            ObjectHandle::Platform => Ok(HierarchyAuth::Platform),
            ObjectHandle::Endorsement => Ok(HierarchyAuth::Endorsement),
            ObjectHandle::Lockout => Ok(HierarchyAuth::Lockout),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl TryFrom<TpmHandle> for HierarchyAuth {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<HierarchyAuth> {
        match tpm_handle {
            TpmHandle::Permanent(permanent_handle) => match permanent_handle {
                PermanentTpmHandle::Owner => Ok(HierarchyAuth::Owner),
                PermanentTpmHandle::Platform => Ok(HierarchyAuth::Platform),
                PermanentTpmHandle::Endorsement => Ok(HierarchyAuth::Endorsement),
                PermanentTpmHandle::Lockout => Ok(HierarchyAuth::Lockout),
                _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
            },
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
// ////////////////////////////////////////////////////////////////////////////////
// TODO: HierarchyPolicy
// ////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
/// Platform
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Platform,
}

impl From<Platform> for AuthHandle {
    fn from(_: Platform) -> AuthHandle {
        AuthHandle::Platform
    }
}

impl TryFrom<AuthHandle> for Platform {
    type Error = Error;

    fn try_from(auth_handle: AuthHandle) -> Result<Platform> {
        match auth_handle {
            AuthHandle::Platform => Ok(Platform::Platform),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Owner
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    Owner,
    Null,
}

impl From<Owner> for ObjectHandle {
    fn from(owner: Owner) -> ObjectHandle {
        match owner {
            Owner::Owner => ObjectHandle::Owner,
            Owner::Null => ObjectHandle::Null,
        }
    }
}

impl TryFrom<ObjectHandle> for Owner {
    type Error = Error;

    fn try_from(object_handle: ObjectHandle) -> Result<Owner> {
        match object_handle {
            ObjectHandle::Owner => Ok(Owner::Owner),
            ObjectHandle::Null => Ok(Owner::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Endorsement
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endorsement {
    Endorsement,
    Null,
}

impl From<Endorsement> for ObjectHandle {
    fn from(endorsement: Endorsement) -> ObjectHandle {
        match endorsement {
            Endorsement::Endorsement => ObjectHandle::Endorsement,
            Endorsement::Null => ObjectHandle::Null,
        }
    }
}

impl TryFrom<ObjectHandle> for Endorsement {
    type Error = Error;

    fn try_from(object_handle: ObjectHandle) -> Result<Endorsement> {
        match object_handle {
            ObjectHandle::Endorsement => Ok(Endorsement::Endorsement),
            ObjectHandle::Null => Ok(Endorsement::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Provision
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provision {
    Owner,
    Platform,
}

impl From<Provision> for AuthHandle {
    fn from(provision: Provision) -> AuthHandle {
        match provision {
            Provision::Owner => AuthHandle::Owner,
            Provision::Platform => AuthHandle::Platform,
        }
    }
}

impl TryFrom<AuthHandle> for Provision {
    type Error = Error;

    fn try_from(auth_handle: AuthHandle) -> Result<Provision> {
        match auth_handle {
            AuthHandle::Owner => Ok(Provision::Owner),
            AuthHandle::Platform => Ok(Provision::Platform),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Clear
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clear {
    Owner,
    Platform,
}

impl From<Clear> for AuthHandle {
    fn from(clear: Clear) -> AuthHandle {
        match clear {
            Clear::Owner => AuthHandle::Owner,
            Clear::Platform => AuthHandle::Platform,
        }
    }
}

impl TryFrom<AuthHandle> for Clear {
    type Error = Error;

    fn try_from(auth_handle: AuthHandle) -> Result<Self> {
        match auth_handle {
            AuthHandle::Owner => Ok(Clear::Owner),
            AuthHandle::Platform => Ok(Clear::Platform),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// NvAuth
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvAuth {
    Platform,
    Owner,
    NvIndex(NvIndexHandle),
}

impl From<NvAuth> for AuthHandle {
    fn from(nv_auth: NvAuth) -> AuthHandle {
        match nv_auth {
            NvAuth::Platform => AuthHandle::Platform,
            NvAuth::Owner => AuthHandle::Owner,
            NvAuth::NvIndex(nv_index_handle) => nv_index_handle.into(),
        }
    }
}

impl TryFrom<AuthHandle> for NvAuth {
    type Error = Error;

    fn try_from(auth_handle: AuthHandle) -> Result<NvAuth> {
        match auth_handle {
            AuthHandle::Platform => Ok(NvAuth::Platform),
            AuthHandle::Owner => Ok(NvAuth::Owner),
            _ => Ok(NvAuth::NvIndex(NvIndexHandle::from(auth_handle))),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Lockout
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lockout {
    Lockout,
}

impl From<Lockout> for ObjectHandle {
    fn from(_: Lockout) -> ObjectHandle {
        ObjectHandle::Lockout
    }
}

impl TryFrom<ObjectHandle> for Lockout {
    type Error = Error;

    fn try_from(object_handle: ObjectHandle) -> Result<Lockout> {
        match object_handle {
            ObjectHandle::Lockout => Ok(Lockout::Lockout),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////
/// NvIndex
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvIndex {
    NvIndex(NvIndexTpmHandle),
}

impl From<NvIndexTpmHandle> for NvIndex {
    fn from(nv_index_tpm_handle: NvIndexTpmHandle) -> NvIndex {
        NvIndex::NvIndex(nv_index_tpm_handle)
    }
}

impl From<NvIndex> for NvIndexTpmHandle {
    fn from(nv_index: NvIndex) -> NvIndexTpmHandle {
        match nv_index {
            NvIndex::NvIndex(handle) => handle,
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////
/// AttachedComponent
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachedComponent {
    AttachedComponent(AttachedComponentTpmHandle),
}

impl From<AttachedComponentTpmHandle> for AttachedComponent {
    fn from(attached_component_tpm_handle: AttachedComponentTpmHandle) -> AttachedComponent {
        AttachedComponent::AttachedComponent(attached_component_tpm_handle)
    }
}

impl From<AttachedComponent> for AttachedComponentTpmHandle {
    fn from(attached_component: AttachedComponent) -> AttachedComponentTpmHandle {
        match attached_component {
            AttachedComponent::AttachedComponent(handle) => handle,
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////
// Act (authenticated timers)
//
// TODO: Figure out how to implement this. This is some kind of counter.
//////////////////////////////////////////////////////////////////////////////////
