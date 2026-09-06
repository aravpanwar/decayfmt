// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use tss_esapi::{
    constants::PcrPropertyTag,
    structures::{PcrSelectSize, PcrSlot, TaggedPcrPropertyList, TaggedPcrSelect},
    tss2_esys::TPML_TAGGED_PCR_PROPERTY,
};

#[test]
fn test_valid_conversions() {
    let expected_tagged_pcr_properties = vec![
        TaggedPcrSelect::create(
            PcrPropertyTag::Auth,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot1, PcrSlot::Slot8, PcrSlot::Slot17],
        )
        .expect("Failed to create TaggedPcrSelect 1"),
        TaggedPcrSelect::create(
            PcrPropertyTag::DrtmReset,
            PcrSelectSize::TwoOctets,
            &[PcrSlot::Slot2, PcrSlot::Slot9],
        )
        .expect("Failed to create TaggedPcrSelect 2"),
        TaggedPcrSelect::create(
            PcrPropertyTag::ExtendL0,
            PcrSelectSize::OneOctet,
            &[
                PcrSlot::Slot4,
                PcrSlot::Slot5,
                PcrSlot::Slot6,
                PcrSlot::Slot7,
            ],
        )
        .expect("Failed to create TaggedPcrSelect 3"),
    ];

    let expected_tpml_tagged_pcr_property: TPML_TAGGED_PCR_PROPERTY =
        expected_tagged_pcr_properties
            .iter()
            .fold(Default::default(), |mut acc, &v| {
                acc.pcrProperty[acc.count as usize] = v.into();
                acc.count += 1;
                acc
            });

    let tagged_pcr_property_list_from_vec: TaggedPcrPropertyList = expected_tagged_pcr_properties
        .clone()
        .try_into()
        .expect("Failed to convert Vec<TaggedPcrSelect> into TaggedPcrPropertyList");

    assert_eq!(
            expected_tagged_pcr_properties.len(),
            tagged_pcr_property_list_from_vec.len(),
            "Mismatch in 'len()' between the Vec<TaggedPcrSelect> and the TaggedPcrPropertyList(from vec)"
        );

    expected_tagged_pcr_properties
            .iter()
            .zip(tagged_pcr_property_list_from_vec.as_ref())
            .for_each(|(expected, actual)| {
                assert_eq!(expected, actual, "Mismatch between an expected TaggedPcrSelect in the Vec<TaggedPcrSelect> the actual tagged property in TaggedPcrPropertyList(from vec)");
            });

    let tagged_pcr_property_list_from_tss: TaggedPcrPropertyList =
        expected_tpml_tagged_pcr_property
            .try_into()
            .expect("Failed to convert TPML_TAGGED_PCR_PROPERTY into TaggedPcrPropertyList");

    assert_eq!(
            expected_tagged_pcr_properties.len(),
            tagged_pcr_property_list_from_tss.len(),
            "Mismatch in 'len()' between the Vec<TaggedPcrSelect> and the TaggedPcrPropertyList(from tss)"
        );

    expected_tagged_pcr_properties
            .iter()
            .zip(tagged_pcr_property_list_from_tss.as_ref())
            .for_each(|(expected, actual)| {
                assert_eq!(expected, actual, "Mismatch between an expected TaggedPcrSelect in the Vec<TaggedPcrSelect> and the actual tagged property in TaggedPcrPropertyList(from tss)");
            });

    let actual_tpml_tagged_pcr_property: TPML_TAGGED_PCR_PROPERTY =
        tagged_pcr_property_list_from_vec.into();

    crate::common::ensure_tpml_tagged_pcr_property_equality(
        &expected_tpml_tagged_pcr_property,
        &actual_tpml_tagged_pcr_property,
    );
}
