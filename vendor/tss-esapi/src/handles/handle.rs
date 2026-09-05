// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! ESYS handle types
//!
//! The ESAPI specification has only one handle type
//! ESYS_TR. That type is wrapped by ObjectHandle but there
//! are also specific handle types that indicates what created
//! them or how they are intended to be used.

pub mod conversions {
    pub(crate) trait TryIntoNotNone {
        fn try_into_not_none(self) -> crate::Result<crate::tss2_esys::ESYS_TR>;
    }
}

/// Macro for generating a basic handle implementation
macro_rules! impl_basic_handle {
    (
        $(#[$outer:meta])*
        $handle_type:ident
    ) => {
        use crate::tss2_esys::ESYS_TR;
        use std::convert::From;

        $(#[$outer])*
        #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
        pub struct $handle_type {
            value: u32,
        }

        impl $handle_type {
            pub fn value(&self) -> u32 {
                self.value
            }
        }

        impl From<ESYS_TR> for $handle_type {
            fn from(tss_esys_object_handle: ESYS_TR) -> $handle_type {
                $handle_type {
                    value: tss_esys_object_handle,
                }
            }
        }

        impl From<$handle_type> for ESYS_TR {
            fn from(handle: $handle_type) -> ESYS_TR {
                handle.value
            }
        }
    };
}

/// Macro for making a esys constant available
/// for a handle type.
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

/// Macro for making the Esys None constant available
/// for a handle type
macro_rules! add_constant_none_handle {
    ($handle_type:ident) => {
        use crate::{
            handles::handle_conversion::TryIntoNotNone, tss2_esys::ESYS_TR_NONE, Error, Result,
            WrapperErrorKind as ErrorKind,
        };
        use log::error;

        add_constant_handle!($handle_type, None, ESYS_TR_NONE);

        impl $handle_type {
            /// Method that returns true if the handle corresponds
            /// to the None handle.
            pub fn is_none(&self) -> bool {
                *self == $handle_type::None
            }
        }

        impl TryIntoNotNone for $handle_type {
            fn try_into_not_none(self) -> Result<ESYS_TR> {
                if !self.is_none() {
                    Ok(self.into())
                } else {
                    error!("Found invalid parameter {}::None", stringify!($handle_type));
                    Err(Error::local_error(ErrorKind::InvalidParam))
                }
            }
        }
    };
}

/// Module for the ObjectHandle
pub mod object {
    use crate::tss2_esys::{
        ESYS_TR_PASSWORD, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_LOCKOUT, ESYS_TR_RH_NULL,
        ESYS_TR_RH_OWNER, ESYS_TR_RH_PLATFORM, ESYS_TR_RH_PLATFORM_NV,
    };

    impl_basic_handle!(
        /// The ObjectHandle is the general handle type
        /// and it wraps the ESYS_TR.
        ///
        /// All the other more specific handle types can be
        /// converted into an ObjectHandle.
        ObjectHandle
    );

    // Add None handle
    add_constant_none_handle!(ObjectHandle);
    // Add all the other constant handles
    add_constant_handle!(ObjectHandle, Password, ESYS_TR_PASSWORD);
    add_constant_handle!(ObjectHandle, Owner, ESYS_TR_RH_OWNER);
    add_constant_handle!(ObjectHandle, Lockout, ESYS_TR_RH_LOCKOUT);
    add_constant_handle!(ObjectHandle, Endorsement, ESYS_TR_RH_ENDORSEMENT);
    add_constant_handle!(ObjectHandle, Platform, ESYS_TR_RH_PLATFORM);
    add_constant_handle!(ObjectHandle, PlatformNv, ESYS_TR_RH_PLATFORM_NV);
    add_constant_handle!(ObjectHandle, Null, ESYS_TR_RH_NULL);
}

/// Macro for creating ESYS_TR conversion for
/// constant handle types
macro_rules! impl_basic_multiple_constant_values_handle {
    ($constant_handle_type:ident) => {
        impl From<$constant_handle_type> for ESYS_TR {
            fn from(constant_handle: $constant_handle_type) -> ESYS_TR {
                // Cannot fail because each value is an ESYS_TR which is defined as u32.
                constant_handle.to_u32().unwrap()
            }
        }

        impl TryFrom<ESYS_TR> for $constant_handle_type {
            type Error = Error;
            fn try_from(tss_esys_handle: ESYS_TR) -> Result<$constant_handle_type> {
                $constant_handle_type::from_u32(tss_esys_handle).ok_or_else(|| {
                    error!(
                        "failed to convert handle into {}",
                        std::stringify!($constant_handle_type)
                    );
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })
            }
        }
    };
}

/// Macro for creating handle conversion
/// from constant handle to a 'non-restricted'
/// handle type
macro_rules! impl_multiple_constant_values_handle_conversion {
    ($constant_handle_type:ident, $handle_type_other:ident) => {
        impl From<$constant_handle_type> for $handle_type_other {
            fn from(constant_handle: $constant_handle_type) -> $handle_type_other {
                // Cannot fail because each value is an ESYS_TR which is defined as u32.
                $handle_type_other::from(constant_handle.to_u32().unwrap())
            }
        }

        impl TryFrom<$handle_type_other> for $constant_handle_type {
            type Error = Error;
            fn try_from(other_handle: $handle_type_other) -> Result<$constant_handle_type> {
                $constant_handle_type::from_u32(other_handle.value()).ok_or_else(|| {
                    error!(
                        "failed to convert handle into {}",
                        std::stringify!($constant_handle_type)
                    );
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })
            }
        }
    };
}

/// PCR handle module
///
/// The specification:
/// "TCG TSS 2.0 Enhanced System API (ESAPI) Specification, Version 1.00, Revision 08, May 28, 2020"
/// specifies preallocated identifiers for PCRs
/// the PcrHandle is a wrapper for those handles.
pub mod pcr {
    use super::object::ObjectHandle;
    use crate::{
        tss2_esys::{
            ESYS_TR, ESYS_TR_PCR0, ESYS_TR_PCR1, ESYS_TR_PCR10, ESYS_TR_PCR11, ESYS_TR_PCR12,
            ESYS_TR_PCR13, ESYS_TR_PCR14, ESYS_TR_PCR15, ESYS_TR_PCR16, ESYS_TR_PCR17,
            ESYS_TR_PCR18, ESYS_TR_PCR19, ESYS_TR_PCR2, ESYS_TR_PCR20, ESYS_TR_PCR21,
            ESYS_TR_PCR22, ESYS_TR_PCR23, ESYS_TR_PCR24, ESYS_TR_PCR25, ESYS_TR_PCR26,
            ESYS_TR_PCR27, ESYS_TR_PCR28, ESYS_TR_PCR29, ESYS_TR_PCR3, ESYS_TR_PCR30,
            ESYS_TR_PCR31, ESYS_TR_PCR4, ESYS_TR_PCR5, ESYS_TR_PCR6, ESYS_TR_PCR7, ESYS_TR_PCR8,
            ESYS_TR_PCR9,
        },
        Error, Result, WrapperErrorKind,
    };

    use log::error;
    use num_derive::{FromPrimitive, ToPrimitive};
    use num_traits::{FromPrimitive, ToPrimitive};
    use std::convert::{From, TryFrom};
    /// PCR handle
    ///
    /// Handles to the pre-allocated
    /// PCR meta data objects.
    #[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
    #[repr(u32)]
    pub enum PcrHandle {
        Pcr0 = ESYS_TR_PCR0,
        Pcr1 = ESYS_TR_PCR1,
        Pcr2 = ESYS_TR_PCR2,
        Pcr3 = ESYS_TR_PCR3,
        Pcr4 = ESYS_TR_PCR4,
        Pcr5 = ESYS_TR_PCR5,
        Pcr6 = ESYS_TR_PCR6,
        Pcr7 = ESYS_TR_PCR7,
        Pcr8 = ESYS_TR_PCR8,
        Pcr9 = ESYS_TR_PCR9,
        Pcr10 = ESYS_TR_PCR10,
        Pcr11 = ESYS_TR_PCR11,
        Pcr12 = ESYS_TR_PCR12,
        Pcr13 = ESYS_TR_PCR13,
        Pcr14 = ESYS_TR_PCR14,
        Pcr15 = ESYS_TR_PCR15,
        Pcr16 = ESYS_TR_PCR16,
        Pcr17 = ESYS_TR_PCR17,
        Pcr18 = ESYS_TR_PCR18,
        Pcr19 = ESYS_TR_PCR19,
        Pcr20 = ESYS_TR_PCR20,
        Pcr21 = ESYS_TR_PCR21,
        Pcr22 = ESYS_TR_PCR22,
        Pcr23 = ESYS_TR_PCR23,
        Pcr24 = ESYS_TR_PCR24,
        Pcr25 = ESYS_TR_PCR25,
        Pcr26 = ESYS_TR_PCR26,
        Pcr27 = ESYS_TR_PCR27,
        Pcr28 = ESYS_TR_PCR28,
        Pcr29 = ESYS_TR_PCR29,
        Pcr30 = ESYS_TR_PCR30,
        Pcr31 = ESYS_TR_PCR31,
    }

    impl_basic_multiple_constant_values_handle!(PcrHandle);
    impl_multiple_constant_values_handle_conversion!(PcrHandle, ObjectHandle);
}

/// Macro for implementing conversion between handles.
macro_rules! impl_handle_conversion {
    ($handle_type_self:ident, $handle_type_other:ident) => {
        impl From<$handle_type_self> for $handle_type_other {
            fn from(handle_self: $handle_type_self) -> $handle_type_other {
                $handle_type_other::from(ESYS_TR::from(handle_self.value))
            }
        }

        impl From<$handle_type_other> for $handle_type_self {
            fn from(handle_other: $handle_type_other) -> $handle_type_self {
                $handle_type_self {
                    value: handle_other.value(),
                }
            }
        }
    };
}

/// Auth handle module
pub mod auth {
    use super::object::ObjectHandle;
    use crate::tss2_esys::{
        ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_LOCKOUT, ESYS_TR_RH_OWNER, ESYS_TR_RH_PLATFORM,
    };
    impl_basic_handle!(
        /// Auth handle
        ///
        /// Represents an esys handle to resources
        /// that can be used for authentication.
        AuthHandle
    );
    impl_handle_conversion!(AuthHandle, ObjectHandle);
    // The following constant handles can be used for authorization
    // according to the TCG TPM2 r1p59 Structures specification.
    add_constant_handle!(AuthHandle, Owner, ESYS_TR_RH_OWNER);
    add_constant_handle!(AuthHandle, Lockout, ESYS_TR_RH_LOCKOUT);
    add_constant_handle!(AuthHandle, Endorsement, ESYS_TR_RH_ENDORSEMENT);
    add_constant_handle!(AuthHandle, Platform, ESYS_TR_RH_PLATFORM);
    // TODO: Figure out how to add AUTH_00 to AUTH_FF range
    // TODO: Figure out how to add ACT_0 to ACT_F range
}

/// NV Index handle module
pub mod nv_index {
    use super::auth::AuthHandle;
    use super::object::ObjectHandle;
    impl_basic_handle!(
        /// NV Index Handle
        ///
        /// Represents an esys resource handle
        /// for a nv index.
        NvIndexHandle
    );
    impl_handle_conversion!(NvIndexHandle, ObjectHandle);
    impl_handle_conversion!(NvIndexHandle, AuthHandle);
}

/// Key handle module
pub mod key {
    use super::object::ObjectHandle;
    use crate::tss2_esys::ESYS_TR_RH_NULL;
    impl_basic_handle!(
        /// Key Handle
        ///
        /// Represents an esys resource handle
        /// for a key.
        KeyHandle
    );
    impl_handle_conversion!(KeyHandle, ObjectHandle);
    add_constant_handle!(KeyHandle, Null, ESYS_TR_RH_NULL);
}

/// Session handle module
pub mod session {
    use super::auth::AuthHandle;
    use super::object::ObjectHandle;
    use crate::tss2_esys::ESYS_TR_PASSWORD;
    impl_basic_handle!(
        /// Session Handle
        ///
        /// Represents an esys handle used for
        /// referencing session resources.
        SessionHandle
    );

    // TSS ESAPI v1p0_r08 specifies that both
    // PASSWORD and NONE can be used as session handles
    // NONE are used when session handle is optional.

    // Add the none handle
    add_constant_none_handle!(SessionHandle);
    // Add all other constant handles
    add_constant_handle!(SessionHandle, Password, ESYS_TR_PASSWORD);

    impl_handle_conversion!(SessionHandle, ObjectHandle);
    impl_handle_conversion!(SessionHandle, AuthHandle);
}
