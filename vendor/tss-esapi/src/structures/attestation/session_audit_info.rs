// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    interface_types::YesNo, structures::Digest, tss2_esys::TPMS_SESSION_AUDIT_INFO, Error, Result,
};
use std::convert::{TryFrom, TryInto};

/// This type holds the attested data for
/// TPM2_GetSessionAuditDigest()
///
/// # Details
/// This corresponds to the TPMS_SESSION_AUDIT_INFO.
#[derive(Debug, Clone)]
pub struct SessionAuditInfo {
    exclusive_session: YesNo,
    session_digest: Digest,
}

impl SessionAuditInfo {
    /// Returns true if if all of the commands recorded in the sessionDigest were
    /// executed without any intervening TPM command that did not use
    /// this audit session
    pub fn exlusive_session(&self) -> bool {
        self.exclusive_session.into()
    }

    /// Returns the current value of the session audit diges
    pub const fn session_digest(&self) -> &Digest {
        &self.session_digest
    }
}

impl From<SessionAuditInfo> for TPMS_SESSION_AUDIT_INFO {
    fn from(session_audit_info: SessionAuditInfo) -> Self {
        TPMS_SESSION_AUDIT_INFO {
            exclusiveSession: session_audit_info.exclusive_session.into(),
            sessionDigest: session_audit_info.session_digest.into(),
        }
    }
}

impl TryFrom<TPMS_SESSION_AUDIT_INFO> for SessionAuditInfo {
    type Error = Error;

    fn try_from(tpms_session_audit_info: TPMS_SESSION_AUDIT_INFO) -> Result<Self> {
        Ok(SessionAuditInfo {
            exclusive_session: tpms_session_audit_info.exclusiveSession.try_into()?,
            session_digest: tpms_session_audit_info.sessionDigest.try_into()?,
        })
    }
}
