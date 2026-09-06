// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    constants::PropertyTag,
    structures::{TaggedProperty, TaggedTpmPropertyList},
    tss2_esys::{TPML_TAGGED_TPM_PROPERTY, TPMS_TAGGED_PROPERTY},
    Error, WrapperErrorKind,
};
#[test]
fn test_valid_conversions() {
    let expected_tagged_properties: Vec<TaggedProperty> = vec![
        TaggedProperty::new(PropertyTag::FamilyIndicator, 8u32),
        TaggedProperty::new(PropertyTag::Level, 12u32),
        TaggedProperty::new(PropertyTag::HrLoadedMin, 24u32),
    ];

    let expected_tpml_tagged_tpm_property: TPML_TAGGED_TPM_PROPERTY = expected_tagged_properties
        .iter()
        .fold(Default::default(), |mut acc, v| {
            acc.tpmProperty[acc.count as usize] = TPMS_TAGGED_PROPERTY::from(*v);
            acc.count += 1;
            acc
        });

    let tagged_tpm_property_list_from_vec: TaggedTpmPropertyList = expected_tagged_properties
        .clone()
        .try_into()
        .expect("Failed to convert Vec<TaggedProoperty> into TaggedTpmPropertyList");

    assert_eq!(
        expected_tagged_properties.len(),
        tagged_tpm_property_list_from_vec.len(),
        "Mismatch in 'len()' between the Vec<TaggedProperty> and the TaggedTpmPropertyList(from vec)"
    );

    expected_tagged_properties
        .iter()
        .zip(tagged_tpm_property_list_from_vec.as_ref())
        .for_each(|(expected, actual)| {
            assert_eq!(expected, actual, "Mismatch between an expected TaggedProperty in the Vec<TaggedProperty> the actual tagged property in TaggedTpmPropertyList(from vec)");
        });

    let tagged_tpm_property_list_from_tss: TaggedTpmPropertyList =
        expected_tpml_tagged_tpm_property
            .try_into()
            .expect("Failed to convert TPML_TAGGED_TPM_PROPERTY into TaggedTpmPropertyList");

    assert_eq!(
        expected_tagged_properties.len(),
        tagged_tpm_property_list_from_tss.len(),
        "Mismatch in 'len()' between the Vec<TaggedProperty> and the TaggedTpmPropertyList(from tss)"
    );

    expected_tagged_properties
        .iter()
        .zip(tagged_tpm_property_list_from_tss.as_ref())
        .for_each(|(expected, actual)| {
            assert_eq!(expected, actual, "Mismatch between an expected TaggedProperty in the Vec<TaggedProperty> the actual tagged property in TaggedTpmPropertyList(from tss)");
        });

    let actual_tpml_tagged_tpm_property: TPML_TAGGED_TPM_PROPERTY =
        tagged_tpm_property_list_from_vec.into();

    crate::common::ensure_tpml_tagged_tpm_property_equality(
        &expected_tpml_tagged_tpm_property,
        &actual_tpml_tagged_tpm_property,
    );
}

#[test]
fn test_invalid_conversions() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        TaggedTpmPropertyList::try_from(vec![TaggedProperty::new(PropertyTag::FamilyIndicator, 8u32); TaggedTpmPropertyList::MAX_SIZE + 1]),
        "Converting a vector with to many elements into a TaggedTpmPropertyList did not produce the expected error",
    );

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        TaggedTpmPropertyList::try_from(TPML_TAGGED_TPM_PROPERTY {
            count: TaggedTpmPropertyList::MAX_SIZE as u32 + 1u32,
            tpmProperty: [Default::default(); 127],
        }),
        "Converting a TPML_TAGGED_TPM_PROPERTY with an invalid 'count' value into a TaggedTpmPropertyList did not produce the expected error",
    );
}

#[test]
fn test_find() {
    let tagged_tpm_property_list: TaggedTpmPropertyList = vec![
        TaggedProperty::new(PropertyTag::FamilyIndicator, 8u32),
        TaggedProperty::new(PropertyTag::Level, 12u32),
        TaggedProperty::new(PropertyTag::HrLoadedMin, 24u32),
    ]
    .try_into()
    .expect("Failed to convert Vec<TaggedProoperty> into TaggedTpmPropertyList");

    assert_eq!(
        &TaggedProperty::new(PropertyTag::FamilyIndicator, 8u32),
        tagged_tpm_property_list
            .find(PropertyTag::FamilyIndicator)
            .expect("Calling find with PropertyTag::FamilyIndicator returned an unexpected 'None'"),
        "'find(PropertyTag::FamilyIndicator)' did not return the expected TaggedProperty value",
    );

    assert_eq!(
        &TaggedProperty::new(PropertyTag::Level, 12u32),
        tagged_tpm_property_list
            .find(PropertyTag::Level)
            .expect("Calling find with PropertyTag::Level returned an unexpected 'None'"),
        "'find(PropertyTag::Level)' did not return the expected TaggedProperty value",
    );

    assert_eq!(
        &TaggedProperty::new(PropertyTag::HrLoadedMin, 24u32),
        tagged_tpm_property_list
            .find(PropertyTag::HrLoadedMin)
            .expect("Calling find with PropertyTag::HrLoadedMin returned an unexpected 'None'"),
        "'find(PropertyTag::HrLoadedMin)' did not return the expected TaggedProperty value",
    );

    assert!(
        tagged_tpm_property_list
            .find(PropertyTag::AlgorithmSet)
            .is_none(),
        "A value that should not exist was found in the TaggedTpmPropertyList"
    );
}
