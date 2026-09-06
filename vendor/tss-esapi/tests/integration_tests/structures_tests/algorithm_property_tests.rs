// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use tss_esapi::{
    attributes::AlgorithmAttributes, constants::AlgorithmIdentifier, structures::AlgorithmProperty,
    tss2_esys::TPMS_ALG_PROPERTY,
};

#[test]
fn test_new() {
    let expected_algorithm_identifier = AlgorithmIdentifier::Rsa;
    let expected_algorithm_properties = AlgorithmAttributes(0x1);
    let algorithm_proprty =
        AlgorithmProperty::new(expected_algorithm_identifier, expected_algorithm_properties);

    assert_eq!(
        expected_algorithm_identifier,
        algorithm_proprty.algorithm_identifier(),
        "AlgorithmProperty, created with new, did not contain expected algorithm identifier value"
    );

    assert_eq!(
        expected_algorithm_properties,
        algorithm_proprty.algorithm_properties(),
        "AlgorithmProperty, created with new, did not contain expected algorithm properties value"
    );
}

#[test]
fn test_conversions() {
    let expected_algorithm_identifier = AlgorithmIdentifier::Rsa;
    let expected_algorithm_properties = AlgorithmAttributes(0x1);

    let expected_tpms_algorithm_property = TPMS_ALG_PROPERTY {
        alg: expected_algorithm_identifier.into(),
        algProperties: expected_algorithm_properties.into(),
    };

    let algorithm_property: AlgorithmProperty = expected_tpms_algorithm_property
        .try_into()
        .expect("Failed to convert TPMS_ALG_PROPERTY into AlgorithmProperty");

    assert_eq!(
        expected_algorithm_identifier,
        algorithm_property.algorithm_identifier(),
        "AlgorithmProperty, converted from TPMS_ALG_PROPERTY, did not contain the expected algorithm identifier value"
    );

    assert_eq!(
        expected_algorithm_properties,
        algorithm_property.algorithm_properties(),
        "AlgorithmProperty, converted from TPMS_ALG_PROPERTY, did not contain the expected algorithm properties value"
    );

    let actual_tpms_algorithm_property: TPMS_ALG_PROPERTY = algorithm_property.into();

    crate::common::ensure_tpms_alg_property_equality(
        &expected_tpms_algorithm_property,
        &actual_tpms_algorithm_property,
    );
}
