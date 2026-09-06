// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::From;
use tss_esapi::{
    handles::{ObjectHandle, SessionHandle},
    tss2_esys::{ESYS_TR, ESYS_TR_NONE, ESYS_TR_PASSWORD},
};

#[test]
fn test_constants_conversions() {
    let conversion_check =
        |esys_handle: ESYS_TR, object_handle: ObjectHandle, session_handle: SessionHandle| {
            assert_eq!(esys_handle, ESYS_TR::from(session_handle));
            assert_eq!(session_handle, SessionHandle::from(esys_handle));
            assert_eq!(object_handle, ObjectHandle::from(session_handle));
            assert_eq!(session_handle, SessionHandle::from(object_handle));
        };

    conversion_check(
        ESYS_TR_PASSWORD,
        ObjectHandle::Password,
        SessionHandle::Password,
    );
    conversion_check(ESYS_TR_NONE, ObjectHandle::None, SessionHandle::None);
}
