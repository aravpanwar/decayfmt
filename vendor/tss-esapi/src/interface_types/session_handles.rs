// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::SessionType, handles::SessionHandle, interface_types::algorithm::HashingAlgorithm,
    Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;

/// Enum representing an policy session interface type
///
/// # Details
/// This corresponds to TPMI_SH_POLICY but provides more
/// information regarding the parameters used when the policy session
/// was created.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PolicySession {
    PolicySession {
        hashing_algorithm: HashingAlgorithm,
        session_handle: SessionHandle,
        session_type: SessionType,
    },
}

impl From<PolicySession> for SessionHandle {
    fn from(policy_session: PolicySession) -> SessionHandle {
        match policy_session {
            PolicySession::PolicySession {
                hashing_algorithm: _,
                session_handle,
                session_type: _,
            } => session_handle,
        }
    }
}

impl From<PolicySession> for AuthSession {
    fn from(policy_session: PolicySession) -> AuthSession {
        AuthSession::PolicySession(policy_session)
    }
}

impl TryFrom<AuthSession> for PolicySession {
    type Error = Error;
    fn try_from(auth_session: AuthSession) -> Result<PolicySession> {
        match auth_session {
            AuthSession::PolicySession(policy_session) => Ok(policy_session),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
/// Enum representing an hmac session interface type
///
/// # Details
/// This corresponds to TPMI_SH_HMAC but provides more
/// information regarding the parameters used when the hmac session
/// was created.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HmacSession {
    HmacSession {
        hashing_algorithm: HashingAlgorithm,
        session_handle: SessionHandle,
    },
}

impl From<HmacSession> for AuthSession {
    fn from(hmac_session: HmacSession) -> AuthSession {
        AuthSession::HmacSession(hmac_session)
    }
}

impl TryFrom<AuthSession> for HmacSession {
    type Error = Error;
    fn try_from(auth_session: AuthSession) -> Result<HmacSession> {
        match auth_session {
            AuthSession::HmacSession(hmac_session) => Ok(hmac_session),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

/// Enum representing an authorization session interface type
///
/// # Details
/// This corresponds to TPMI_SH_AUTH_SESSION but provides more
/// information regarding the parameters used when the AuthSession
/// was created.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuthSession {
    HmacSession(HmacSession),
    PolicySession(PolicySession),
    Password,
}

impl AuthSession {
    /// Function that creates a `Option<Session>`.
    ///
    /// If a Session is created from the NoneHandle
    /// then the returned value from the function will be None.
    pub fn create(
        session_type: SessionType,
        session_handle: SessionHandle,
        auth_hash: HashingAlgorithm,
    ) -> Option<AuthSession> {
        if session_handle != SessionHandle::None {
            Some(match session_type {
                SessionType::Hmac => {
                    //AuthSession::HmacSession(HmacSessionData::new(auth_hash, session_handle))
                    AuthSession::HmacSession(HmacSession::HmacSession {
                        hashing_algorithm: auth_hash,
                        session_handle,
                    })
                }
                SessionType::Policy => AuthSession::PolicySession(PolicySession::PolicySession {
                    hashing_algorithm: auth_hash,
                    session_handle,
                    session_type,
                }),
                SessionType::Trial => AuthSession::PolicySession(PolicySession::PolicySession {
                    hashing_algorithm: auth_hash,
                    session_handle,
                    session_type,
                }),
            })
        } else {
            None
        }
    }
}

impl From<AuthSession> for SessionHandle {
    fn from(auth_session: AuthSession) -> SessionHandle {
        match auth_session {
            AuthSession::HmacSession(HmacSession::HmacSession {
                hashing_algorithm: _,
                session_handle,
            }) => session_handle,
            AuthSession::PolicySession(PolicySession::PolicySession {
                hashing_algorithm: _,
                session_handle,
                session_type: _,
            }) => session_handle,
            AuthSession::Password => SessionHandle::Password,
        }
    }
}

impl From<Option<AuthSession>> for SessionHandle {
    fn from(optional_auth_session: Option<AuthSession>) -> SessionHandle {
        if let Some(auth_session) = optional_auth_session {
            auth_session.into()
        } else {
            SessionHandle::None
        }
    }
}
