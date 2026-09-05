// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    constants::AlgorithmIdentifier,
    interface_types::{algorithm::HashingAlgorithm, YesNo},
    structures::{AttestInfo, Digest, MaxNvBuffer, Name, PcrSelectionListBuilder, PcrSlot},
    tss2_esys::{
        TPMS_CERTIFY_INFO, TPMS_CLOCK_INFO, TPMS_COMMAND_AUDIT_INFO, TPMS_CREATION_INFO,
        TPMS_NV_CERTIFY_INFO, TPMS_QUOTE_INFO, TPMS_SESSION_AUDIT_INFO, TPMS_TIME_ATTEST_INFO,
        TPMS_TIME_INFO, TPMU_ATTEST,
    },
};

use std::convert::{TryFrom, TryInto};

#[test]
fn test_certify_into_tpm_type_conversions() {
    let expected_tpms_certify_info = TPMS_CERTIFY_INFO {
        name: Name::try_from(vec![0xffu8; 64])
            .expect("Failed to create name")
            .into(),
        qualifiedName: Name::try_from(vec![0x0fu8; 64])
            .expect("Failed to create qualified name")
            .into(),
    };

    let tpmu_attest: TPMU_ATTEST = AttestInfo::Certify {
        info: expected_tpms_certify_info
            .try_into()
            .expect("Failed to convert TPMS_CERTIFY_INFO to certifyInfo"),
    }
    .into();

    let actual_tpms_certify_info = unsafe { &tpmu_attest.certify };

    crate::common::ensure_tpms_certify_info_equality(
        &expected_tpms_certify_info,
        actual_tpms_certify_info,
    );
}

#[test]
fn test_quote_into_tpm_type_conversions() {
    let expected_tpms_quote_info = TPMS_QUOTE_INFO {
        pcrSelect: PcrSelectionListBuilder::new()
            .with_selection(
                HashingAlgorithm::Sha256,
                &[
                    PcrSlot::Slot1,
                    PcrSlot::Slot2,
                    PcrSlot::Slot3,
                    PcrSlot::Slot4,
                ],
            )
            .build()
            .expect("Failed to create PcrSelectionList")
            .into(),
        pcrDigest: Digest::try_from(vec![0xffu8; 32])
            .expect("Failed to create digest")
            .into(),
    };

    let tpmu_attest: TPMU_ATTEST = AttestInfo::Quote {
        info: expected_tpms_quote_info
            .try_into()
            .expect("Failed to create QuoteInfo from TPMS_QUOTE_INFO"),
    }
    .into();

    let actual_tpms_quote_info = unsafe { &tpmu_attest.quote };

    crate::common::ensure_tpms_quote_info_equality(
        &expected_tpms_quote_info,
        actual_tpms_quote_info,
    );
}

#[test]
fn test_session_audit_into_tpm_type_conversions() {
    let expected_tpms_session_audit_info = TPMS_SESSION_AUDIT_INFO {
        exclusiveSession: YesNo::Yes.into(),
        sessionDigest: Digest::try_from(vec![0xffu8; 32])
            .expect("Failed to session digest")
            .into(),
    };

    let tpmu_attest: TPMU_ATTEST = AttestInfo::SessionAudit {
        info: expected_tpms_session_audit_info
            .try_into()
            .expect("Unable to convert TPMS_SESSION_AUDIT_INFO into SessionAuditInfo"),
    }
    .into();

    let actual_tpms_session_audit = unsafe { &tpmu_attest.sessionAudit };

    crate::common::ensure_tpms_session_audit_info_equality(
        &expected_tpms_session_audit_info,
        actual_tpms_session_audit,
    );
}

#[test]
fn test_command_audit_into_tpm_type_conversions() {
    let expected_tpms_command_audit_info = TPMS_COMMAND_AUDIT_INFO {
        auditCounter: 1u64,
        digestAlg: AlgorithmIdentifier::from(HashingAlgorithm::Sha512).into(),
        auditDigest: Digest::try_from(vec![0xffu8; 32])
            .expect("Failed to create audit digest")
            .into(),
        commandDigest: Digest::try_from(vec![0xf0u8; 32])
            .expect("Failed to create command digest")
            .into(),
    };

    let tpmu_attest: TPMU_ATTEST = AttestInfo::CommandAudit {
        info: expected_tpms_command_audit_info
            .try_into()
            .expect("Unable to convert TPMS_SESSION_AUDIT_INFO into SessionAuditInfo"),
    }
    .into();

    let actual_tpms_command_audit = unsafe { &tpmu_attest.commandAudit };

    crate::common::ensure_tpms_command_audit_info_equality(
        &expected_tpms_command_audit_info,
        actual_tpms_command_audit,
    );
}

#[test]
fn test_time_into_tpm_type_conversions() {
    let expected_tpms_time_attest_info = TPMS_TIME_ATTEST_INFO {
        time: TPMS_TIME_INFO {
            time: 12u64,
            clockInfo: TPMS_CLOCK_INFO {
                clock: 1u64,
                resetCount: 2u32,
                restartCount: 3u32,
                safe: YesNo::Yes.into(),
            },
        },
        firmwareVersion: 0xfffffu64,
    };

    let tpmu_attest: TPMU_ATTEST = AttestInfo::Time {
        info: expected_tpms_time_attest_info
            .try_into()
            .expect("Unable to convert TPMS_TIME_ATTEST_INFO into TimeAttestInfo"),
    }
    .into();

    let actual_tpms_time_attest_info = unsafe { &tpmu_attest.time };

    crate::common::ensure_tpms_time_attest_info_equality(
        &expected_tpms_time_attest_info,
        actual_tpms_time_attest_info,
    );
}

#[test]
fn test_creation_into_tpm_type_conversions() {
    let expected_tpms_creation_info = TPMS_CREATION_INFO {
        objectName: Name::try_from(vec![0xf0u8; 68])
            .expect("Failed to create object name")
            .into(),
        creationHash: Digest::try_from(vec![0xffu8; 32])
            .expect("Failed to create creation digest")
            .into(),
    };

    let tpmu_attest: TPMU_ATTEST = AttestInfo::Creation {
        info: expected_tpms_creation_info
            .try_into()
            .expect("Failed to convert TPMS_CREATION_INFO into CreationInfo"),
    }
    .into();

    let actual_tpms_creation_info = unsafe { &tpmu_attest.creation };

    crate::common::ensure_tpms_creation_info_equality(
        &expected_tpms_creation_info,
        actual_tpms_creation_info,
    );
}

#[test]
fn test_nv_into_tpm_type_conversions() {
    let expected_tpms_nv_certify_info = TPMS_NV_CERTIFY_INFO {
        indexName: Name::try_from(vec![0xf0u8; 68])
            .expect("Failed to create index name")
            .into(),
        offset: 12u16,
        nvContents: MaxNvBuffer::try_from(vec![0xfc; 2048])
            .expect("Failed to create nv contents")
            .into(),
    };

    let tpmu_attest: TPMU_ATTEST = AttestInfo::Nv {
        info: expected_tpms_nv_certify_info
            .try_into()
            .expect("Failed to convert TPMS_NV_CERTIFY_INFO into NvCertifyInfo"),
    }
    .into();

    let actual_tpms_nv_certify_info = unsafe { &tpmu_attest.nv };

    crate::common::ensure_tpms_nv_certify_info_equality(
        &expected_tpms_nv_certify_info,
        actual_tpms_nv_certify_info,
    );
}
