// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    structures::{MaxNvBuffer, Name, NvCertifyInfo},
    tss2_esys::TPMS_NV_CERTIFY_INFO,
};

#[test]
fn test_conversion() {
    let expected_index_name =
        Name::try_from(vec![0xf0u8; 68]).expect("Failed to create index name");
    let expected_offset = 12u16;
    let expected_nv_contents =
        MaxNvBuffer::try_from(vec![0xfc; 2048]).expect("Failed to create nv contents");
    let expected_tpms_nv_certify_info = TPMS_NV_CERTIFY_INFO {
        indexName: expected_index_name.clone().into(),
        offset: expected_offset,
        nvContents: expected_nv_contents.clone().into(),
    };

    let nv_certify_info: NvCertifyInfo = expected_tpms_nv_certify_info
        .try_into()
        .expect("Failed to convert TPMS_NV_CERTIFY_INFO into NvCertifyInfo");
    assert_eq!(
        &expected_index_name,
        nv_certify_info.index_name(),
        "The NvCertifyInfo converted from TPMS_NV_CERTIFY_INFO did not contain correct value for 'index name'",
    );
    assert_eq!(
        expected_offset,
        nv_certify_info.offset(),
        "The NvCertifyInfo converted from TPMS_NV_CERTIFY_INFO did not contain correct value for 'offset'",
    );
    assert_eq!(
        &expected_nv_contents,
        nv_certify_info.nv_contents(),
        "The NvCertifyInfo converted from TPMS_NV_CERTIFY_INFO did not contain correct value for 'nv contents'",
    );

    let actual_tpms_nv_certify_info: TPMS_NV_CERTIFY_INFO = nv_certify_info.into();

    crate::common::ensure_tpms_nv_certify_info_equality(
        &expected_tpms_nv_certify_info,
        &actual_tpms_nv_certify_info,
    );
}
