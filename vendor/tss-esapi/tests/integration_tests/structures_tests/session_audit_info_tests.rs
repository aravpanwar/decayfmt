// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    interface_types::YesNo,
    structures::{Digest, SessionAuditInfo},
    tss2_esys::TPMS_SESSION_AUDIT_INFO,
};

#[test]
fn test_conversion() {
    let expected_exclusive_session = YesNo::Yes;
    let expected_session_digest =
        Digest::try_from(vec![0xffu8; 32]).expect("Failed to session digest");
    let expected_tpms_session_audit_info = TPMS_SESSION_AUDIT_INFO {
        exclusiveSession: expected_exclusive_session.into(),
        sessionDigest: expected_session_digest.clone().into(),
    };

    let session_audit_info = SessionAuditInfo::try_from(expected_tpms_session_audit_info)
        .expect("Unable to convert TPMS_SESSION_AUDIT_INFO into SessionAuditInfo");

    assert_eq!(
        bool::from(expected_exclusive_session),
        session_audit_info.exlusive_session(),
        "The SessionAuditInfo that was converted from TPMS_SESSION_AUDIT_INFO, did not contain the expected value for 'exclusive session'",
    );

    assert_eq!(
        &expected_session_digest,
        session_audit_info.session_digest(),
        "The SessionAuditInfo that was converted from TPMS_SESSION_AUDIT_INFO, did not contain the expected value for 'session digest'",
    );

    let actual_tpms_session_audit_info: TPMS_SESSION_AUDIT_INFO = session_audit_info.into();

    crate::common::ensure_tpms_session_audit_info_equality(
        &expected_tpms_session_audit_info,
        &actual_tpms_session_audit_info,
    );
}
