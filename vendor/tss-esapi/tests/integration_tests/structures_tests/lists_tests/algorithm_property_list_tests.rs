// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    attributes::AlgorithmAttributes,
    constants::AlgorithmIdentifier,
    structures::{AlgorithmProperty, AlgorithmPropertyList},
    tss2_esys::{TPML_ALG_PROPERTY, TPMS_ALG_PROPERTY},
    Error, WrapperErrorKind,
};

use std::convert::{TryFrom, TryInto};

#[test]
fn test_conversions() {
    let expected_algorithm_properties = [
        (AlgorithmIdentifier::Rsa, AlgorithmAttributes(1)),
        (AlgorithmIdentifier::Aes, AlgorithmAttributes(2)),
    ];

    let expected_tpml_alg_property = expected_algorithm_properties.iter().fold(
        TPML_ALG_PROPERTY::default(),
        |mut acc, (aid, aa)| {
            acc.algProperties[acc.count as usize].alg = (*aid).into();
            acc.algProperties[acc.count as usize].algProperties = (*aa).into();
            acc.count += 1;
            acc
        },
    );

    let actual_algorithm_property_list: AlgorithmPropertyList = expected_tpml_alg_property
        .try_into()
        .expect("Failed to convert TPML_ALG_PROPERTY into AlgorithmPropertyList");

    assert_eq!(
        expected_algorithm_properties.len(), actual_algorithm_property_list.len(),
        "The algorithm property list converted from TPML_ALG_PROPERTY did not contain the expected amount of elements"
    );

    expected_algorithm_properties
        .iter()
        .zip(actual_algorithm_property_list.iter())
        .for_each(|((expected_aid, expected_aa), ap)| {
            assert_eq!(
                expected_aid, &ap.algorithm_identifier(),
                "An AlgorithmProperty in the AlgorithmPropertyList converted from TPML_ALG_PROPERTY did not contain the expected algorithm identifer"
            );
            assert_eq!(
                expected_aa, &ap.algorithm_properties(),
                "An AlgorithmProperty in the AlgorithmPropertyList converted from TPML_ALG_PROPERTY did not contain the expected algorithm properties"
            );
        });

    let actual_tpml_alg_property: TPML_ALG_PROPERTY = actual_algorithm_property_list.into();

    crate::common::ensure_tpml_alg_property_equality(
        &expected_tpml_alg_property,
        &actual_tpml_alg_property,
    );
}

#[test]
fn test_valid_conversion_vector() {
    let expected_algorithm_properties = [
        (AlgorithmIdentifier::Rsa, AlgorithmAttributes(1)),
        (AlgorithmIdentifier::Aes, AlgorithmAttributes(2)),
    ];

    let expected_tpml_alg_property = expected_algorithm_properties.iter().fold(
        TPML_ALG_PROPERTY::default(),
        |mut acc, (aid, aa)| {
            acc.algProperties[acc.count as usize].alg = (*aid).into();
            acc.algProperties[acc.count as usize].algProperties = (*aa).into();
            acc.count += 1;
            acc
        },
    );

    let expected_algorithm_property_list: AlgorithmPropertyList = expected_tpml_alg_property
        .try_into()
        .expect("Failed to convert TPML_ALG_PROPERTY into AlgorithmPropertyList");

    assert_eq!(
        expected_algorithm_properties.len(), expected_algorithm_property_list.len(),
        "The algorithm property list converted from TPML_ALG_PROPERTY did not contain the expected amount of elements"
    );

    let algorithm_properties_vector: Vec<AlgorithmProperty> =
        expected_algorithm_property_list.clone().into();

    expected_algorithm_properties
        .iter()
        .zip(algorithm_properties_vector.iter())
        .for_each(|((expected_aid, expected_aa), ap)| {
            assert_eq!(
                expected_aid, &ap.algorithm_identifier(),
                "An AlgorithmProperty in the Vec<AlgorithmProperty> converted from AlgorithmPropertyList did not contain the expected algorithm identifer"
            );
            assert_eq!(
                expected_aa, &ap.algorithm_properties(),
                "An AlgorithmProperty in the Vec<AlgorithmProperty> converted from AlgorithmPropertyList did not contain the expected algorithm properties"
            );
        });

    let actual_algorithm_property_list: AlgorithmPropertyList = algorithm_properties_vector
        .try_into()
        .expect("Failed to convert Vec<AlgorithmProperty> into AlgorithmPropertyList");

    expected_algorithm_property_list
            .iter()
            .zip(actual_algorithm_property_list.iter())
            .for_each(|(expected, actual)| {
                assert_eq!(
                    expected, actual, "AlgorithmPropertyList converted from Vec<AlgorithmProperty> did not contain the expected algorithm property"
                );
            });
}

#[test]
fn test_invalid_conversion_from_tpml_alg_property() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        AlgorithmPropertyList::try_from(TPML_ALG_PROPERTY {
            count: AlgorithmPropertyList::MAX_SIZE as u32 + 1u32,
            ..Default::default()
        }),
        "Converting a TPML_ALG_PROPERTY with invalid 'count' into AlgorithmPropertyList did not produce the expected error"
    );
}

#[test]
fn test_invalid_conversion_from_vector() {
    let value: AlgorithmProperty = TPMS_ALG_PROPERTY {
        alg: AlgorithmIdentifier::Aes.into(),
        algProperties: AlgorithmAttributes(2).into(),
    }
    .try_into()
    .expect("Failed to convert TPMS_ALG_PROPERTY into AlgorithmProperty");

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        AlgorithmPropertyList::try_from(vec![value; AlgorithmPropertyList::MAX_SIZE + 1]),
        "Converting a Vec<AlgorithmProperty> with invalid number of items into AlgorithmPropertyList did not produce the expected error"
    );
}
