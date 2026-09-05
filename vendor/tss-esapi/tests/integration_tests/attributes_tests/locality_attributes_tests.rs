// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    attributes::{LocalityAttributes, LocalityAttributesBuilder},
    tss2_esys::TPMA_LOCALITY,
    Error, WrapperErrorKind,
};

#[test]
fn test_conversions() {
    for locality in 0u8..=4u8 {
        let expected_locality_attributes = LocalityAttributesBuilder::new()
            .with_locality(locality)
            .build()
            .expect("Failed to build locality attributes");
        let tpma_locality: TPMA_LOCALITY = expected_locality_attributes.into();
        assert_eq!(
            1u8.checked_shl(locality.into())
                .expect("Unable to create locality value"),
            tpma_locality,
            "Locality did not convert into expected TPMA_LOCALITY value"
        );
        assert_eq!(
            expected_locality_attributes,
            tpma_locality.into(),
            "The locality attributes converted from TPMA_LOCALITY did not match the expected value"
        );
    }

    for locality in 32u8..=u8::MAX {
        let expected_locality_attributes = LocalityAttributesBuilder::new()
            .with_locality(locality)
            .build()
            .expect("Failed to build locality attributes");

        let tpma_locality: TPMA_LOCALITY = expected_locality_attributes.into();
        assert_eq!(
            locality, tpma_locality,
            "Locality did not convert into expected TPMA_LOCALITY value"
        );

        assert_eq!(
            expected_locality_attributes,
            tpma_locality.into(),
            "The locality attributes converted from TPMA_LOCALITY did not match the expected value"
        );
    }
}

#[test]
fn test_constants() {
    assert_eq!(
        LocalityAttributes::LOCALITY_ZERO,
        LocalityAttributesBuilder::new()
            .with_locality(0)
            .build()
            .expect("Failed to build locality attributes"),
        "LOCALITY_ZERO constant does not have the correct value"
    );

    assert_eq!(
        LocalityAttributes::LOCALITY_ONE,
        LocalityAttributesBuilder::new()
            .with_locality(1)
            .build()
            .expect("Failed to build locality attributes"),
        "LOCALITY_ONE constant does not have the correct value"
    );

    assert_eq!(
        LocalityAttributes::LOCALITY_TWO,
        LocalityAttributesBuilder::new()
            .with_locality(2)
            .build()
            .expect("Failed to build locality attributes"),
        "LOCALITY_TWO constant does not have the correct value"
    );

    assert_eq!(
        LocalityAttributes::LOCALITY_THREE,
        LocalityAttributesBuilder::new()
            .with_locality(3)
            .build()
            .expect("Failed to build locality attributes"),
        "LOCALITY_THREE constant does not have the correct value"
    );

    assert_eq!(
        LocalityAttributes::LOCALITY_FOUR,
        LocalityAttributesBuilder::new()
            .with_locality(4)
            .build()
            .expect("Failed to build locality attributes"),
        "LOCALITY_FOUR constant does not have the correct value"
    );
}

#[test]
fn test_builder_valid_non_extended() {
    let locality_attributes = LocalityAttributesBuilder::new()
        .with_localities(&[0, 1, 2, 3, 4])
        .build()
        .expect("Failed to build locality attributes");

    assert!(
        locality_attributes.locality_zero(),
        "Locality ZERO was not properly set"
    );
    assert!(
        locality_attributes.locality_one(),
        "Locality ONE was not properly set"
    );
    assert!(
        locality_attributes.locality_two(),
        "Locality TWO was not properly set"
    );
    assert!(
        locality_attributes.locality_three(),
        "Locality THREE was not properly set"
    );
    assert!(
        locality_attributes.locality_four(),
        "Locality FOUR was not properly set"
    );
    assert!(
        !locality_attributes.is_extended(),
        "Locality attributes unexpectedly indicated extended"
    );
}

#[test]
fn test_builder_valid_extended() {
    for expected_locality in 32u8..=u8::MAX {
        let locality_attributes = LocalityAttributesBuilder::new()
            .with_locality(expected_locality)
            .build()
            .expect("Failed to build locality attributes");
        assert!(
            locality_attributes.is_extended(),
            "Locality attributes does not indicate to be 'extnded' as expected"
        );
        assert_eq!(
            expected_locality,
            locality_attributes
                .as_extended()
                .expect("Failed to get local attributes as extended"),
            "The extended value does not match expected value.",
        );
    }
}

#[test]
fn test_invalid_locality() {
    for locality in 5u8..=31u8 {
        assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
            LocalityAttributesBuilder::new()
                .with_locality(locality)
                .build(),
            "Locality builder did not produce expected error when using locality {}",
            locality
        );
    }
}

#[test]
fn test_invalid_extended_locality() {
    for locality in 0u8..=4u8 {
        let locality_attributes = LocalityAttributesBuilder::new()
            .with_locality(locality)
            .build()
            .expect("Failed to get local attributes as extended");

        assert!(
            !locality_attributes.is_extended(),
            "The non extended locality {} is unexpectedly indicating that it is extended",
            locality
        );

        assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
            locality_attributes.as_extended(),
            "Calling as_extended() on locality {} that is not extended, did not result in the expected error", locality,
        );
    }
}

#[test]
fn test_invalid_locality_combinataions() {
    for locality in 0u8..=4u8 {
        assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
            LocalityAttributesBuilder::new()
                .with_locality(32)
                .with_locality(locality)
                .build(),
            "Locality builder did not produce expected error when using locality 32 in combination with locality {}",
            locality,
        );
    }

    for locality in 32u8..u8::MAX {
        assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
            LocalityAttributesBuilder::new()
                .with_locality(1)
                .with_locality(locality)
                .build(),
            "Locality builder did not produce expected error when using locality 32 in combination with locality {}",
            locality,
        );
    }
}
