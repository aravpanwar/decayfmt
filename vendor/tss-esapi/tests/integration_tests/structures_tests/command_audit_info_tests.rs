// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    constants::AlgorithmIdentifier,
    interface_types::algorithm::HashingAlgorithm,
    structures::{CommandAuditInfo, Digest},
    tss2_esys::TPMS_COMMAND_AUDIT_INFO,
};

#[test]
fn test_conversion() {
    let expected_audit_counter = 1u64;
    let expected_hashing_algorithm = HashingAlgorithm::Sha512;
    let expected_audit_digest =
        Digest::try_from(vec![0xffu8; 32]).expect("Failed to create audit digest");
    let expected_command_digest =
        Digest::try_from(vec![0xf0u8; 32]).expect("Failed to create command digest");
    let expected_tpms_command_audit_info = TPMS_COMMAND_AUDIT_INFO {
        auditCounter: expected_audit_counter,
        digestAlg: AlgorithmIdentifier::from(expected_hashing_algorithm).into(),
        auditDigest: expected_audit_digest.clone().into(),
        commandDigest: expected_command_digest.clone().into(),
    };
    let command_audit_info: CommandAuditInfo = expected_tpms_command_audit_info
        .try_into()
        .expect("Failed to convert TPMS_COMMAND_AUDIT_INFO into CommandAuditInfo");

    assert_eq!(
        expected_audit_counter,
        command_audit_info.audit_counter(),
        "The CommandAuditInfo converted from TPMS_COMMAND_AUDIT_INFO did not contain correct value for 'audit counter'",
    );
    assert_eq!(
        expected_hashing_algorithm,
        command_audit_info.hashing_algorithm(),
        "The CommandAuditInfo converted from TPMS_COMMAND_AUDIT_INFO did not contain correct value for 'hashing algorithm'",
    );
    assert_eq!(
        &expected_audit_digest,
        command_audit_info.audit_digest(),
        "The CommandAuditInfo converted from TPMS_COMMAND_AUDIT_INFO did not contain correct value for 'audit digest'",
    );
    assert_eq!(
        &expected_command_digest,
        command_audit_info.command_digest(),
        "The CommandAuditInfo converted from TPMS_COMMAND_AUDIT_INFO did not contain correct value for 'command digest'",
    );

    let actual_tpms_command_audit_info: TPMS_COMMAND_AUDIT_INFO = command_audit_info.into();

    crate::common::ensure_tpms_command_audit_info_equality(
        &expected_tpms_command_audit_info,
        &actual_tpms_command_audit_info,
    );
}
