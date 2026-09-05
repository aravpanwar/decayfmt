// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    handles::{AuthHandle, ObjectHandle},
    tss2_esys::{
        ESYS_TR, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_LOCKOUT, ESYS_TR_RH_OWNER, ESYS_TR_RH_PLATFORM,
    },
};

#[test]
fn test_constants_conversions() {
    let conversion_check =
        |esys_handle: ESYS_TR, object_handle: ObjectHandle, auth_handle: AuthHandle| {
            assert_eq!(esys_handle, ESYS_TR::from(auth_handle));
            assert_eq!(auth_handle, AuthHandle::from(esys_handle));
            assert_eq!(object_handle, ObjectHandle::from(auth_handle));
            assert_eq!(auth_handle, AuthHandle::from(object_handle));
        };

    // Check conversion of esys handles to TPM constants
    conversion_check(ESYS_TR_RH_OWNER, ObjectHandle::Owner, AuthHandle::Owner);
    conversion_check(
        ESYS_TR_RH_LOCKOUT,
        ObjectHandle::Lockout,
        AuthHandle::Lockout,
    );
    conversion_check(
        ESYS_TR_RH_ENDORSEMENT,
        ObjectHandle::Endorsement,
        AuthHandle::Endorsement,
    );
    conversion_check(
        ESYS_TR_RH_PLATFORM,
        ObjectHandle::Platform,
        AuthHandle::Platform,
    );
}
