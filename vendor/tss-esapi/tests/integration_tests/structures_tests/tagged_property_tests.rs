// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    constants::PropertyTag, structures::TaggedProperty, tss2_esys::TPMS_TAGGED_PROPERTY,
};

use std::convert::TryInto;

#[test]
fn test_conversions() {
    let expected_property = PropertyTag::AlgorithmSet;
    let expected_value = 1u32;

    let expected_tpms_tagged_property = TPMS_TAGGED_PROPERTY {
        property: expected_property.into(),
        value: expected_value,
    };

    let tagged_property: TaggedProperty = expected_tpms_tagged_property
        .try_into()
        .expect("Failed to convert TPMS_TAGGED_PROPERTY");

    assert_eq!(
        tagged_property.property(),
        expected_property,
        "Converted TaggedProperty did not contain the expected property value"
    );

    assert_eq!(
        tagged_property.value(),
        expected_value,
        "Converted TaggedProperty did not contain expected value in the value field",
    );

    let actual_tpms_tagged_property: TPMS_TAGGED_PROPERTY = tagged_property.into();

    crate::common::ensure_tpms_tagged_property_equality(
        &expected_tpms_tagged_property,
        &actual_tpms_tagged_property,
    );
}
