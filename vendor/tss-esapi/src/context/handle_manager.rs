// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{handles::ObjectHandle, tss2_esys::ESYS_TR, Error, Result, WrapperErrorKind};
use log::error;
use std::collections::HashMap;

/// Enum representing the action to be taken
/// when the handle is dropped.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HandleDropAction {
    Close,
    Flush,
}

/// The HandleManager is responsible for storing
/// the handles used by Context iand their states.
/// In order to make sure the correct handles get
/// flushed and closed when the Context is dropped.
#[derive(Debug)]
pub struct HandleManager {
    open_handles: HashMap<ObjectHandle, HandleDropAction>,
}

impl HandleManager {
    /// Creates a new HandleManager
    pub fn new() -> HandleManager {
        HandleManager {
            open_handles: HashMap::new(),
        }
    }

    /// Adds a handle to the HandleManager
    pub fn add_handle(
        &mut self,
        handle: ObjectHandle,
        handle_drop_action: HandleDropAction,
    ) -> Result<()> {
        if handle == ObjectHandle::None || handle == ObjectHandle::Null {
            error!("Handle manager does not handle None or Null handles");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        // The TSS might return the same handle, see #383
        if let Some(stored_handle_drop_action) = self.open_handles.get(&handle) {
            if handle_drop_action != *stored_handle_drop_action {
                error!("Handle drop action inconsistency");
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
        }
        let _ = self.open_handles.insert(handle, handle_drop_action);
        Ok(())
    }

    /// Sets the handle as flushed which removes it from the manager.
    ///
    /// # Errors
    /// If the handle was not set to be flushed then this will cause an
    /// error but the handle will still be removed from the handler.
    pub fn set_as_flushed(&mut self, handle: ObjectHandle) -> Result<()> {
        self.open_handles
            .remove(&handle)
            .ok_or_else(|| {
                error!("Handle({}) does not exist", ESYS_TR::from(handle));
                Error::local_error(WrapperErrorKind::InvalidHandleState)
            })
            .and_then(|handle_drop_action| {
                if handle_drop_action == HandleDropAction::Flush {
                    Ok(())
                } else {
                    error!(
                        "Flushing handle({}) that should not have been flushed.",
                        ESYS_TR::from(handle)
                    );
                    Err(Error::local_error(WrapperErrorKind::InvalidHandleState))
                }
            })
    }

    /// Sets the handles as closed which removes it from the handler.
    ///
    /// # Errors
    /// If the handle was set to be flushed then this will cause an
    /// error but the handle will still be removed from the handler.
    pub fn set_as_closed(&mut self, handle: ObjectHandle) -> Result<()> {
        self.open_handles
            .remove(&handle)
            .ok_or_else(|| {
                error!("Handle({}) does not exist", ESYS_TR::from(handle));
                Error::local_error(WrapperErrorKind::InvalidHandleState)
            })
            .and_then(|handle_drop_action| {
                if handle_drop_action == HandleDropAction::Close {
                    Ok(())
                } else {
                    error!(
                        "Closing handle({}) that should have been flushed",
                        ESYS_TR::from(handle)
                    );
                    Err(Error::local_error(WrapperErrorKind::InvalidHandleState))
                }
            })
    }

    /// Retrieves all handles that needs to be flushed.
    pub fn handles_to_flush(&self) -> Vec<ObjectHandle> {
        self.open_handles
            .iter()
            .filter_map(|(open_handle, &handle_drop_action)| {
                if handle_drop_action == HandleDropAction::Flush {
                    Some(open_handle)
                } else {
                    None
                }
            })
            .cloned()
            .collect::<Vec<ObjectHandle>>()
    }

    /// Retrieves all handles that needs to be closed.
    pub fn handles_to_close(&self) -> Vec<ObjectHandle> {
        self.open_handles
            .iter()
            .filter_map(|(open_handle, &handle_drop_action)| {
                if handle_drop_action == HandleDropAction::Close {
                    Some(open_handle)
                } else {
                    None
                }
            })
            .cloned()
            .collect::<Vec<ObjectHandle>>()
    }

    /// Indicates if the manager has any open handles
    pub fn has_open_handles(&self) -> bool {
        !self.open_handles.is_empty()
    }
}
