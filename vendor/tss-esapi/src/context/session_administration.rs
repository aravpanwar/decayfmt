// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    attributes::{SessionAttributes, SessionAttributesMask},
    handles::SessionHandle,
    interface_types::session_handles::AuthSession,
    tss2_esys::{Esys_TRSess_GetAttributes, Esys_TRSess_SetAttributes},
    Context, Error, Result,
};
use log::error;

impl Context {
    /// Set the given attributes on a given session.
    pub fn tr_sess_set_attributes(
        &mut self,
        session: AuthSession,
        attributes: SessionAttributes,
        mask: SessionAttributesMask,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_TRSess_SetAttributes(
                self.mut_context(),
                SessionHandle::from(session).into(),
                attributes.into(),
                mask.into(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when setting session attributes: {}", ret);
            Err(ret)
        }
    }

    /// Get session attribute flags.
    pub fn tr_sess_get_attributes(&mut self, session: AuthSession) -> Result<SessionAttributes> {
        let mut flags = 0;
        let ret = unsafe {
            Esys_TRSess_GetAttributes(
                self.mut_context(),
                SessionHandle::from(session).into(),
                &mut flags,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(SessionAttributes(flags))
        } else {
            error!("Error when getting session attributes: {}", ret);
            Err(ret)
        }
    }

    // Missing function: Esys_TRSess_GetNonceTPM
}
