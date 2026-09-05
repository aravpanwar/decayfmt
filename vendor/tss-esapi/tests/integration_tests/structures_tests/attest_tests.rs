// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    constants::{tss::TPM2_GENERATED_VALUE, AlgorithmIdentifier},
    interface_types::{algorithm::HashingAlgorithm, structure_tags::AttestationType, YesNo},
    structures::{
        Attest, AttestInfo, ClockInfo, Data, Digest, MaxNvBuffer, Name, PcrSelectionListBuilder,
        PcrSlot, TimeAttestInfo,
    },
    traits::{Marshall, UnMarshall},
    tss2_esys::{
        TPMS_ATTEST, TPMS_CERTIFY_INFO, TPMS_CLOCK_INFO, TPMS_COMMAND_AUDIT_INFO,
        TPMS_CREATION_INFO, TPMS_NV_CERTIFY_INFO, TPMS_QUOTE_INFO, TPMS_SESSION_AUDIT_INFO,
        TPMS_TIME_ATTEST_INFO, TPMS_TIME_INFO,
    },
};

use std::convert::{TryFrom, TryInto};

#[test]
fn test_attest_with_certify_info_into_tpm_type_conversions() {
    let expected_certify_info_name =
        Name::try_from(vec![0xffu8; 64]).expect("Failed to create name");
    let expected_certify_info_qualified_name =
        Name::try_from(vec![0x0fu8; 64]).expect("Failed to create qualified name");
    let expected_attest_info = AttestInfo::Certify {
        info: TPMS_CERTIFY_INFO {
            name: expected_certify_info_name.clone().into(),
            qualifiedName: expected_certify_info_qualified_name.clone().into(),
        }
        .try_into()
        .expect("Failed to convert TPMS_CERTIFY_INFO to CertifyInfo"),
    };

    let (attest, expected_tpms_attest) =
        create_validated_test_parameters(expected_attest_info, AttestationType::Certify);

    if let AttestInfo::Certify { info } = attest.attested() {
        assert_eq!(
            &expected_certify_info_name,
            info.name(),
            "CertifyInfo did not contain expected name",
        );
        assert_eq!(
            &expected_certify_info_qualified_name,
            info.qualified_name(),
            "CertifyInfo did not contain expected qualified name",
        );
    } else {
        panic!("Converted Attest did not contain expected value for 'attest info'");
    }

    let actual_tpms_attest: TPMS_ATTEST = attest.into();

    crate::common::ensure_tpms_attest_equality(&expected_tpms_attest, &actual_tpms_attest);
}

#[test]
fn test_attest_with_quote_info_into_tpm_type_conversions() {
    let expected_pcr_selection = PcrSelectionListBuilder::new()
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
        .expect("Failed to create PcrSelectionList");
    let expected_pcr_digest = Digest::try_from(vec![0xffu8; 32]).expect("Failed to create digest");
    let expected_attest_info = AttestInfo::Quote {
        info: TPMS_QUOTE_INFO {
            pcrSelect: expected_pcr_selection.clone().into(),
            pcrDigest: expected_pcr_digest.clone().into(),
        }
        .try_into()
        .expect("Failed to convert TPMS_QUOTE_INFO to QuoteInfo"),
    };

    let (attest, expected_tpms_attest) =
        create_validated_test_parameters(expected_attest_info, AttestationType::Quote);

    if let AttestInfo::Quote { info } = attest.attested() {
        assert_eq!(
            &expected_pcr_selection,
            info.pcr_selection(),
            "QuoteInfo did not contain expected pcr selection",
        );
        assert_eq!(
            &expected_pcr_digest,
            info.pcr_digest(),
            "QuoteInfo did not contain expected pcr digest",
        );
    } else {
        panic!("Converted Attest did not contain expected value for 'attest info'");
    }

    let actual_tpms_attest: TPMS_ATTEST = attest.into();

    crate::common::ensure_tpms_attest_equality(&expected_tpms_attest, &actual_tpms_attest);
}

#[test]
fn test_attest_with_session_audit_info_into_tpm_type_conversions() {
    let expected_exclusive_session = YesNo::Yes;
    let expected_session_digest =
        Digest::try_from(vec![0xffu8; 32]).expect("Failed to session digest");
    let expected_attest_info = AttestInfo::SessionAudit {
        info: TPMS_SESSION_AUDIT_INFO {
            exclusiveSession: expected_exclusive_session.into(),
            sessionDigest: expected_session_digest.clone().into(),
        }
        .try_into()
        .expect("Failed to convert TPMS_SESSION_AUDIT_INFO to SessionAuditInfo"),
    };

    let (attest, expected_tpms_attest) =
        create_validated_test_parameters(expected_attest_info, AttestationType::SessionAudit);

    if let AttestInfo::SessionAudit { info } = attest.attested() {
        assert_eq!(
            expected_exclusive_session,
            info.exlusive_session().into(),
            "SessionAuditInfo did not contain expected exclusive session",
        );
        assert_eq!(
            &expected_session_digest,
            info.session_digest(),
            "SessionAuditInfo did not contain expected session digest",
        );
    } else {
        panic!("Converted Attest did not contain expected value for 'attest info'");
    }

    let actual_tpms_attest: TPMS_ATTEST = attest.into();

    crate::common::ensure_tpms_attest_equality(&expected_tpms_attest, &actual_tpms_attest);
}

#[test]
fn test_attest_with_command_audit_info_into_tpm_type_conversions() {
    let expected_audit_counter = 1u64;
    let expected_digest_alg = HashingAlgorithm::Sha512;
    let expected_audit_digest =
        Digest::try_from(vec![0xffu8; 32]).expect("Failed to create audit digest");
    let expected_command_digest =
        Digest::try_from(vec![0xf0u8; 32]).expect("Failed to create command digest");
    let expected_attest_info = AttestInfo::CommandAudit {
        info: TPMS_COMMAND_AUDIT_INFO {
            auditCounter: expected_audit_counter,
            digestAlg: AlgorithmIdentifier::from(expected_digest_alg).into(),
            auditDigest: expected_audit_digest.clone().into(),
            commandDigest: expected_command_digest.clone().into(),
        }
        .try_into()
        .expect("Failed to convert TPMS_COMMAND_AUDIT_INFO to CommandAuditInfo"),
    };

    let (attest, expected_tpms_attest) =
        create_validated_test_parameters(expected_attest_info, AttestationType::CommandAudit);

    if let AttestInfo::CommandAudit { info } = attest.attested() {
        assert_eq!(
            expected_audit_counter,
            info.audit_counter(),
            "CommandAuditInfo did not contain expected audit counter",
        );
        assert_eq!(
            expected_digest_alg,
            info.hashing_algorithm(),
            "CommandAuditInfo did not contain expected hashing algorithm",
        );
        assert_eq!(
            &expected_audit_digest,
            info.audit_digest(),
            "CommandAuditInfo did not contain expected audit digest",
        );
        assert_eq!(
            &expected_command_digest,
            info.command_digest(),
            "CommandAuditInfo did not contain expected command digest",
        );
    } else {
        panic!("Converted Attest did not contain expected value for 'attest info'");
    }

    let actual_tpms_attest: TPMS_ATTEST = attest.into();

    crate::common::ensure_tpms_attest_equality(&expected_tpms_attest, &actual_tpms_attest);
}

#[test]
fn test_attest_with_time_info_into_tpm_type_conversions() {
    let expected_time_attest_info: TimeAttestInfo = TPMS_TIME_ATTEST_INFO {
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
    }
    .try_into()
    .expect("Failed to convert TPMS_TIME_ATTEST_INFO to TimeAttestInfo");

    let expected_attest_info = AttestInfo::Time {
        info: expected_time_attest_info,
    };

    let (attest, expected_tpms_attest) =
        create_validated_test_parameters(expected_attest_info, AttestationType::Time);

    if let AttestInfo::Time { info } = attest.attested() {
        assert_eq!(
            &expected_time_attest_info, info,
            "TimeAttestValue did not contain expected values",
        );
    } else {
        panic!("Converted Attest did not contain expected value for 'attest info'");
    }

    let actual_tpms_attest: TPMS_ATTEST = attest.into();

    crate::common::ensure_tpms_attest_equality(&expected_tpms_attest, &actual_tpms_attest);
}

#[test]
fn test_attest_with_creation_info_into_tpm_type_conversions() {
    let expected_object_name =
        Name::try_from(vec![0xf0u8; 68]).expect("Failed to create object name");
    let expected_creation_hash =
        Digest::try_from(vec![0xffu8; 32]).expect("Failed to create creation digest");

    let expected_attest_info = AttestInfo::Creation {
        info: TPMS_CREATION_INFO {
            objectName: expected_object_name.clone().into(),
            creationHash: expected_creation_hash.clone().into(),
        }
        .try_into()
        .expect("Failed to convert TPMS_CREATION_INFO to CreationInfo"),
    };

    let (attest, expected_tpms_attest) =
        create_validated_test_parameters(expected_attest_info, AttestationType::Creation);

    if let AttestInfo::Creation { info } = attest.attested() {
        assert_eq!(
            &expected_object_name,
            info.object_name(),
            "CreationInfo did not contain expected value for object name",
        );
        assert_eq!(
            &expected_creation_hash,
            info.creation_hash(),
            "CreationInfo did not contain expected value for creation hash",
        );
    } else {
        panic!("Converted Attest did not contain expected value for 'attest info'");
    }

    let actual_tpms_attest: TPMS_ATTEST = attest.into();

    crate::common::ensure_tpms_attest_equality(&expected_tpms_attest, &actual_tpms_attest);
}

#[test]
fn test_attest_with_nv_creation_info_into_tpm_type_conversions() {
    let expected_index_name =
        Name::try_from(vec![0xf0u8; 68]).expect("Failed to create index name");
    let expected_offset = 12u16;
    let expected_nv_contents =
        MaxNvBuffer::try_from(vec![0xfc; 2048]).expect("Failed to create nv contents");
    let expected_attest_info = AttestInfo::Nv {
        info: TPMS_NV_CERTIFY_INFO {
            indexName: expected_index_name.clone().into(),
            offset: expected_offset,
            nvContents: expected_nv_contents.clone().into(),
        }
        .try_into()
        .expect("Failed to convert TPMS_NV_CERTIFY_INFO to NvCreationInfo"),
    };

    let (attest, expected_tpms_attest) =
        create_validated_test_parameters(expected_attest_info, AttestationType::Nv);

    if let AttestInfo::Nv { info } = attest.attested() {
        assert_eq!(
            &expected_index_name,
            info.index_name(),
            "NvCreationInfo did not contain expected value for index name",
        );
        assert_eq!(
            expected_offset,
            info.offset(),
            "NvCreationInfo did not contain expected value for offset",
        );
        assert_eq!(
            &expected_nv_contents,
            info.nv_contents(),
            "NvCreationInfo did not contain expected value for nv contents",
        );
    } else {
        panic!("Converted Attest did not contain expected value for 'attest info'");
    }

    let actual_tpms_attest: TPMS_ATTEST = attest.into();

    crate::common::ensure_tpms_attest_equality(&expected_tpms_attest, &actual_tpms_attest);
}

#[test]
fn test_marshall_and_unmarshall() {
    let expected_index_name =
        Name::try_from(vec![0xf0u8; 68]).expect("Failed to create index name");
    let expected_offset = 12u16;
    let expected_nv_contents =
        MaxNvBuffer::try_from(vec![0xfc; 2048]).expect("Failed to create nv contents");
    let expected_attest_info = AttestInfo::Nv {
        info: TPMS_NV_CERTIFY_INFO {
            indexName: expected_index_name.clone().into(),
            offset: expected_offset,
            nvContents: expected_nv_contents.clone().into(),
        }
        .try_into()
        .expect("Failed to convert TPMS_NV_CERTIFY_INFO to NvCreationInfo"),
    };

    let expected_qualified_signer =
        Name::try_from(vec![0x0eu8; 64]).expect("Failed to create qualified name");
    let expected_extra_data =
        Data::try_from(vec![0x0du8; 64]).expect("Failed to create extra data");
    let expected_clock_info = ClockInfo::try_from(TPMS_CLOCK_INFO {
        clock: 1u64,
        resetCount: 2u32,
        restartCount: 3u32,
        safe: YesNo::Yes.into(),
    })
    .expect("Failed to create clock info");
    let expected_firmware_version = 1u64;

    let expected_tpms_attest = TPMS_ATTEST {
        magic: TPM2_GENERATED_VALUE,
        type_: AttestationType::Nv.into(),
        qualifiedSigner: expected_qualified_signer.clone().into(),
        extraData: expected_extra_data.clone().into(),
        clockInfo: expected_clock_info.into(),
        firmwareVersion: expected_firmware_version,
        attested: expected_attest_info.into(),
    };

    let attest =
        Attest::try_from(expected_tpms_attest).expect("Failed to convert TPMS_ATTEST to Attest");

    let marshalled_attest = attest.marshall().expect("Failed to marshall data");
    assert!(
        !marshalled_attest.is_empty(),
        "The marshalled attest did not contain any data"
    );

    let un_marshalled_data =
        Attest::unmarshall(&marshalled_attest).expect("Failed to unmarshall data");

    assert_eq!(
        AttestationType::Nv,
        un_marshalled_data.attestation_type(),
        "UnMarshalled Attest did not contain expected value for 'attestation type'"
    );
    assert_eq!(
        &expected_qualified_signer,
        un_marshalled_data.qualified_signer(),
        "UnMarshalled Attest did not contain expected value for 'qualified signer'"
    );
    assert_eq!(
        &expected_extra_data,
        un_marshalled_data.extra_data(),
        "UnMarshalled Attest did not contain expected value for 'extra data'",
    );
    assert_eq!(
        &expected_clock_info,
        un_marshalled_data.clock_info(),
        "UnMarshalled Attest did not contain expected value for 'clock info'",
    );
    assert_eq!(
        expected_firmware_version,
        un_marshalled_data.firmware_version(),
        "UnMarshalled Attest did not contain expected value for 'firmware version'",
    );

    if let AttestInfo::Nv { info } = un_marshalled_data.attested() {
        assert_eq!(
            &expected_index_name,
            info.index_name(),
            "NvCreationInfo, in the UnMarshalled data, did not contain expected value for index name",
        );
        assert_eq!(
            expected_offset,
            info.offset(),
            "NvCreationInfo, in the UnMarshalled data, did not contain expected value for offset",
        );
        assert_eq!(
            &expected_nv_contents,
            info.nv_contents(),
            "NvCreationInfo, in the UnMarshalled data, did not contain expected value for nv contents",
        );
    } else {
        panic!("UnMarshalled Attest did not contain expected value for 'attest info'");
    }
}

fn create_validated_test_parameters(
    expected_attest_info: AttestInfo,
    expected_attestation_type: AttestationType,
) -> (Attest, TPMS_ATTEST) {
    let expected_qualified_signer =
        Name::try_from(vec![0x0eu8; 64]).expect("Failed to create qualified name");
    let expected_extra_data =
        Data::try_from(vec![0x0du8; 64]).expect("Failed to create extra data");
    let expected_clock_info = ClockInfo::try_from(TPMS_CLOCK_INFO {
        clock: 1u64,
        resetCount: 2u32,
        restartCount: 3u32,
        safe: YesNo::Yes.into(),
    })
    .expect("Failed to create clock info");
    let expected_firmware_version = 1u64;

    let expected_tpms_attest = TPMS_ATTEST {
        magic: TPM2_GENERATED_VALUE,
        type_: expected_attestation_type.into(),
        qualifiedSigner: expected_qualified_signer.clone().into(),
        extraData: expected_extra_data.clone().into(),
        clockInfo: expected_clock_info.into(),
        firmwareVersion: expected_firmware_version,
        attested: expected_attest_info.into(),
    };

    let attest =
        Attest::try_from(expected_tpms_attest).expect("Failed to convert TPMS_ATTEST to Attest");

    assert_eq!(
        expected_attestation_type,
        attest.attestation_type(),
        "Converted Attest did not contain expected value for 'attestation type'"
    );
    assert_eq!(
        &expected_qualified_signer,
        attest.qualified_signer(),
        "Converted Attest did not contain expected value for 'qualified signer'"
    );
    assert_eq!(
        &expected_extra_data,
        attest.extra_data(),
        "Converted Attest did not contain expected value for 'extra data'",
    );
    assert_eq!(
        &expected_clock_info,
        attest.clock_info(),
        "Converted Attest did not contain expected value for 'clock info'",
    );
    assert_eq!(
        expected_firmware_version,
        attest.firmware_version(),
        "Converted Attest did not contain expected value for 'firmware version'",
    );

    (attest, expected_tpms_attest)
}
