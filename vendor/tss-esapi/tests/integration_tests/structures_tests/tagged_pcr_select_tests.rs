// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryInto;
use tss_esapi::{
    constants::PcrPropertyTag,
    structures::{PcrSelectSize, PcrSlot, TaggedPcrSelect},
    tss2_esys::TPMS_TAGGED_PCR_SELECT,
};

#[test]
fn test_conversions() {
    let expected_pcr_property_tag = PcrPropertyTag::ExtendL0;
    let expected_size_of_select = PcrSelectSize::ThreeOctets;
    let expected_pcr_slots = vec![
        PcrSlot::Slot1,
        PcrSlot::Slot8,
        PcrSlot::Slot16,
        PcrSlot::Slot17,
    ]; // [2, 1, 3, X], X doesn't matter because size of select is three octets

    let expected_tpms_tagged_pcr_select = TPMS_TAGGED_PCR_SELECT {
        tag: expected_pcr_property_tag.into(),
        sizeofSelect: expected_size_of_select.as_u8(),
        pcrSelect: [2, 1, 3, 0],
    };

    let tagged_pcr_select: TaggedPcrSelect = expected_tpms_tagged_pcr_select
        .try_into()
        .expect("Failed to convert TPMS_TAGGED_PCR_SELECT into TaggedPcrSelect");

    assert_eq!(
        expected_pcr_property_tag,
        tagged_pcr_select.pcr_property_tag(),
        "Converted TaggedPcrSelect did not contain the expected pcr property tag value"
    );

    assert_eq!(
        expected_size_of_select,
        tagged_pcr_select.size_of_select(),
        "Converted TaggedPcrSelect did not contain the expected size of select value"
    );

    assert_eq!(
        expected_pcr_slots,
        tagged_pcr_select.selected_pcrs(),
        "Converted TaggedPcrSelect did not contain the expected PCR slot values"
    );

    let actual_tpms_tagged_pcr_select: TPMS_TAGGED_PCR_SELECT = tagged_pcr_select.into();

    crate::common::ensure_tpms_tagged_pcr_select_equality(
        &expected_tpms_tagged_pcr_select,
        &actual_tpms_tagged_pcr_select,
    );
}
