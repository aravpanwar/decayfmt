// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    structures::{CreationInfo, Digest, Name},
    tss2_esys::TPMS_CREATION_INFO,
};

#[test]
fn test_conversion() {
    let expected_object_name =
        Name::try_from(vec![0xf0u8; 68]).expect("Failed to create object name");
    let expected_creation_hash =
        Digest::try_from(vec![0xffu8; 32]).expect("Failed to create creation digest");
    let expected_tpms_creation_info = TPMS_CREATION_INFO {
        objectName: expected_object_name.clone().into(),
        creationHash: expected_creation_hash.clone().into(),
    };

    let creation_info: CreationInfo = expected_tpms_creation_info
        .try_into()
        .expect("Failed to convert TPMS_CREATION_INFO into CreationInfo");

    assert_eq!(
        &expected_object_name,
        creation_info.object_name(),
        "The CommandAuditInfo converted from TPMS_CREATION_INFO did not contain correct value for 'object name'",
    );

    assert_eq!(
        &expected_creation_hash,
        creation_info.creation_hash(),
        "The CommandAuditInfo converted from TPMS_CREATION_INFO did not contain correct value for 'creation hash'",
    );

    let actual_tpms_creation_info: TPMS_CREATION_INFO = creation_info.into();

    crate::common::ensure_tpms_creation_info_equality(
        &expected_tpms_creation_info,
        &actual_tpms_creation_info,
    );
}
