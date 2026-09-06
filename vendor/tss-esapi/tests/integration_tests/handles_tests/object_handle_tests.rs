// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::From;
use tss_esapi::{
    handles::ObjectHandle,
    tss2_esys::{
        ESYS_TR, ESYS_TR_NONE, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_LOCKOUT, ESYS_TR_RH_NULL,
        ESYS_TR_RH_OWNER, ESYS_TR_RH_PLATFORM, ESYS_TR_RH_PLATFORM_NV,
    },
};

#[test]
fn test_constants_conversions() {
    // closure used for the repeated tests
    let conversion_check = |esys_handle: ESYS_TR, object_handle: ObjectHandle| {
        assert_eq!(esys_handle, ESYS_TR::from(object_handle));
        assert_eq!(object_handle, ObjectHandle::from(esys_handle));
    };

    // Check conversion of esys handles to TPM constants
    conversion_check(ESYS_TR_RH_OWNER, ObjectHandle::Owner);
    conversion_check(ESYS_TR_RH_NULL, ObjectHandle::Null);
    conversion_check(ESYS_TR_RH_LOCKOUT, ObjectHandle::Lockout);
    conversion_check(ESYS_TR_RH_ENDORSEMENT, ObjectHandle::Endorsement);
    conversion_check(ESYS_TR_RH_PLATFORM, ObjectHandle::Platform);
    conversion_check(ESYS_TR_RH_PLATFORM_NV, ObjectHandle::PlatformNv);
    conversion_check(ESYS_TR_NONE, ObjectHandle::None);
}
