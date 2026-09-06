// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::constants::response_code::Tss2ResponseCode;
use crate::tss2_esys::TSS2_RC;
/// Main error type used by the crate to return issues with a method call. The value can either be
/// a TSS-generated response code or a wrapper error - marking an issue caught within the wrapping
/// layer.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    WrapperError(WrapperErrorKind),
    Tss2Error(Tss2ResponseCode),
}

impl Error {
    pub(crate) fn from_tss_rc(rc: TSS2_RC) -> Self {
        Error::Tss2Error(Tss2ResponseCode::from_tss_rc(rc))
    }

    pub(crate) fn local_error(kind: WrapperErrorKind) -> Self {
        Error::WrapperError(kind)
    }

    /// Verify whether the value contained is a success response code.
    pub fn is_success(self) -> bool {
        if let Error::Tss2Error(tss2_rc) = self {
            tss2_rc.is_success()
        } else {
            false
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WrapperError(e) => e.fmt(f),
            Error::Tss2Error(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::WrapperError(wrapper_error) => Some(wrapper_error),
            Error::Tss2Error(response_code) => Some(response_code),
        }
    }
}

/// List of error types that might occur in the wrapper.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WrapperErrorKind {
    /// Returned when a size or length-defined parameter does not conform with the size
    /// restrictions for it.
    WrongParamSize,
    /// Returned when a required parameter was not passed, usually to a builder.
    ParamsMissing,
    /// Returned when two or more parameters have inconsistent values or variants.
    InconsistentParams,
    /// Returned when the value of a parameter is not yet supported.
    UnsupportedParam,
    /// Returned when the value of a parameter is invalid for that type.
    InvalidParam,
    /// Returned when the TPM returns an invalid value from a call.
    WrongValueFromTpm,
    /// Returned when a session for authentication has not been set
    /// before the call is made.
    MissingAuthSession,
    /// Returned when a handle is required to be in a specific state
    /// (i.g. Open, Flushed, Closed) but it is not.
    InvalidHandleState,
    /// An unexpected internal error occurred.
    InternalError,
}

impl std::fmt::Display for WrapperErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrapperErrorKind::WrongParamSize => {
                write!(f, "parameter provided is of the wrong size")
            }
            WrapperErrorKind::ParamsMissing => {
                write!(f, "some of the required parameters were not provided")
            }
            WrapperErrorKind::InconsistentParams => write!(
                f,
                "the provided parameters have inconsistent values or variants"
            ),
            WrapperErrorKind::UnsupportedParam => write!(
                f,
                "the provided parameter is not yet supported by the library"
            ),
            WrapperErrorKind::InvalidParam => {
                write!(f, "the provided parameter is invalid for that type.")
            }
            WrapperErrorKind::WrongValueFromTpm => write!(f, "the TPM returned an invalid value."),
            WrapperErrorKind::MissingAuthSession => write!(f, "Missing authorization session"),
            WrapperErrorKind::InvalidHandleState => write!(f, "Invalid handle state"),
            WrapperErrorKind::InternalError => {
                write!(f, "an unexpected error occurred within the crate")
            }
        }
    }
}

impl std::error::Error for WrapperErrorKind {}
