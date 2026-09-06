// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::handles::TpmHandle;
use crate::tss2_esys::{TPM2_HANDLE, TPML_HANDLE};
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::TryFrom;
use std::ops::Deref;

/// A list of TPM handles
///
/// # Details
/// This corresponds to `TPML_HANDLE`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandleList {
    handles: Vec<TpmHandle>,
}

impl HandleList {
    pub const MAX_SIZE: usize = Self::calculate_max_size();

    pub fn new() -> Self {
        HandleList {
            handles: Vec::new(),
        }
    }

    /// Adds a handle to the current list of handles.
    pub fn add(&mut self, handle: TpmHandle) -> Result<()> {
        if self.handles.len() + 1 > HandleList::MAX_SIZE {
            error!(
                "Adding TPM handle to list will make the list exceeded its maximum count(> {})",
                HandleList::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        self.handles.push(handle);
        Ok(())
    }

    /// Returns the inner type.
    pub fn into_inner(self) -> Vec<TpmHandle> {
        self.handles
    }

    /// Private function that calculates the maximum number
    /// elements allowed in internal storage.
    const fn calculate_max_size() -> usize {
        crate::structures::capability_data::max_cap_size::<TPM2_HANDLE>()
    }
}

impl TryFrom<TPML_HANDLE> for HandleList {
    type Error = Error;

    fn try_from(handles: TPML_HANDLE) -> Result<Self> {
        let handle_count = handles.count as usize;
        if handle_count > Self::MAX_SIZE {
            error!("Error: Invalid TPML_HANDLE count(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        handles.handle[..handle_count]
            .iter()
            .map(|&cc| TpmHandle::try_from(cc))
            .collect::<Result<Vec<TpmHandle>>>()
            .map(|handles| HandleList { handles })
    }
}

impl From<HandleList> for TPML_HANDLE {
    fn from(handles: HandleList) -> Self {
        let mut tss_handles: TPML_HANDLE = Default::default();
        for handle in handles.handles {
            tss_handles.handle[tss_handles.count as usize] = handle.into();
            tss_handles.count += 1;
        }
        tss_handles
    }
}

impl TryFrom<Vec<TpmHandle>> for HandleList {
    type Error = Error;

    fn try_from(handles: Vec<TpmHandle>) -> Result<Self> {
        if handles.len() > Self::MAX_SIZE {
            error!("Error: Invalid TPML_HANDLE count(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(HandleList { handles })
    }
}

impl From<HandleList> for Vec<TpmHandle> {
    fn from(handle_list: HandleList) -> Self {
        handle_list.handles
    }
}

impl AsRef<[TpmHandle]> for HandleList {
    fn as_ref(&self) -> &[TpmHandle] {
        self.handles.as_slice()
    }
}

impl Deref for HandleList {
    type Target = Vec<TpmHandle>;

    fn deref(&self) -> &Self::Target {
        &self.handles
    }
}
