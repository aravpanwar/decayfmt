// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    attributes::{SessionAttributes, SessionAttributesBuilder, SessionAttributesMask},
    tss2_esys::TPMA_SESSION,
};

macro_rules! test_valid_conversion {
    ($tpm_value:expr, $method:ident) => {
        let tpma_session_attribute: TPMA_SESSION = $tpm_value;
        let session_attributes = SessionAttributes::from(tpma_session_attribute);
        assert_eq!(
            true,
            session_attributes.$method(),
            "SessionAttributes converted from TPMA_SESSION = {} did not produce the expected result with regard to {}.", tpma_session_attribute, stringify!($method),
        );
        assert_eq!(
            tpma_session_attribute,
            session_attributes.into(),
            "Converting session attributes with {} set did not convert into the expected TPMA_SESSION value", std::stringify!($method),
        );
    };
}

macro_rules! test_valid_mask_conversion {
    ($tpm_value:expr, $attribute:tt) => {
        let tpma_session_attribute: TPMA_SESSION = $tpm_value;
        let session_attributes_mask = SessionAttributesMask::from(tpma_session_attribute);
        assert_eq!(
            tpma_session_attribute,
            session_attributes_mask.into(),
            "Converting session attributes mask with {} set did not convert into the expected TPMA_SESSION value", $attribute,
        );
    };
}

#[test]
fn test_valid_session_attributes_conversions() {
    test_valid_conversion!(
        1u8.checked_shl(0)
            .expect("Failed to create 'continue session' value"),
        continue_session
    );
    test_valid_conversion!(
        1u8.checked_shl(1)
            .expect("Failed to create 'audit exclusive' value"),
        audit_exclusive
    );
    test_valid_conversion!(
        1u8.checked_shl(2)
            .expect("Failed to create 'audit reset' value"),
        audit_reset
    );
    test_valid_conversion!(
        1u8.checked_shl(5)
            .expect("Failed to create 'decrypt' value"),
        decrypt
    );
    test_valid_conversion!(
        1u8.checked_shl(6)
            .expect("Failed to create 'encrypt' value"),
        encrypt
    );
    test_valid_conversion!(
        1u8.checked_shl(7).expect("Failed to create 'audit' value"),
        audit
    );
}

#[ignore]
#[test]
fn test_invalid_session_attributes_conversions() {
    // bit 3 and 4 are reserved and shall be cleared.
    // No error for this is implemented.
    // See https://github.com/parallaxsecond/rust-tss-esapi/issues/330
}

#[test]
fn test_valid_session_attributes_mask_conversions() {
    test_valid_mask_conversion!(
        1u8.checked_shl(0)
            .expect("Failed to create 'use continue session' mask value"),
        "use_continue_session"
    );
    test_valid_mask_conversion!(
        1u8.checked_shl(1)
            .expect("Failed to create 'use audit exclusive' mask value"),
        "use_audit_exclusive"
    );
    test_valid_mask_conversion!(
        1u8.checked_shl(2)
            .expect("Failed to create 'use audit reset' mask value"),
        "use_audit_reset"
    );
    test_valid_mask_conversion!(
        1u8.checked_shl(5)
            .expect("Failed to create 'use decrypt' mask value"),
        "use_decrypt"
    );
    test_valid_mask_conversion!(
        1u8.checked_shl(6)
            .expect("Failed to 'use encrypt' mask value"),
        "use encrypt"
    );
    test_valid_mask_conversion!(
        1u8.checked_shl(7)
            .expect("Failed to create 'use audit' session value"),
        "use audit"
    );
}

#[ignore]
#[test]
fn test_invalid_session_attributes_mask_conversions() {
    // bit 3 and 4 are reserved and shall be cleared.
    // No error for this is implemented.
    // See https://github.com/parallaxsecond/rust-tss-esapi/issues/330
}

#[test]
fn test_session_attributes_builder_constructing() {
    let _b1 = SessionAttributes::builder();
    let _b2 = SessionAttributesMask::builder();
    let _b3 = SessionAttributesBuilder::default();
    let _b4 = SessionAttributesBuilder::new();
}

#[test]
fn test_builder_from_session_attributes() {
    let (attributes, mask) = SessionAttributes::builder().build();
    assert_eq!(SessionAttributes::from(0), attributes, "Building session attributes without anything set using SessionAttributes::builder() did not produce expected result");
    assert_eq!(SessionAttributesMask::from(0), mask, "Building sesssion attributes mask without anything set using SessionAttributes::builder() did not produce expected result")
}

#[test]
fn test_builder_from_session_attributes_mask() {
    let (attributes, mask) = SessionAttributesMask::builder().build();
    assert_eq!(SessionAttributes::from(0), attributes, "Building session attributes without anything set using SessionAttributesMask::builder() did not produce expected result");
    assert_eq!(SessionAttributesMask::from(0), mask, "Building sesssion attributes mask without anything set using SessionAttributesMask::builder() did not produce expected result")
}

#[test]
fn test_builder_from_session_attributes_builder_default() {
    let (attributes, mask) = SessionAttributesBuilder::default().build();
    assert_eq!(SessionAttributes::from(0), attributes, "Building session attributes without anything set using SessionAttributesBuilder::default() did not produce expected result");
    assert_eq!(SessionAttributesMask::from(0), mask, "Building sesssion attributes mask without anything set using SessionAttributesBuilder::default() did not produce expected result")
}

#[test]
fn test_builder_from_session_attributes_builder_new() {
    let (attributes, mask) = SessionAttributesBuilder::new().build();
    assert_eq!(SessionAttributes::from(0), attributes, "Building session attributes without anything set using SessionAttributesBuilder::new() did not produce expected result");
    assert_eq!(SessionAttributesMask::from(0), mask, "Building sesssion attributes mask without anything set using SessionAttributesBuilder::new() did not produce expected result")
}

#[test]
fn test_session_attributes_builder() {
    let expected_session_attributes = SessionAttributes::from(0b11100111u8);
    let expected_session_attributes_mask = SessionAttributesMask::from(0b11100111u8);

    let (actual_session_attributes, actual_session_attributes_mask) =
        SessionAttributesBuilder::new()
            .with_continue_session(true)
            .with_audit_exclusive(true)
            .with_audit_reset(true)
            .with_decrypt(true)
            .with_encrypt(true)
            .with_audit(true)
            .build();

    assert_eq!(
        expected_session_attributes, actual_session_attributes,
        "SessionAttributes builder did not produce the expected session attributes value"
    );
    assert_eq!(
        expected_session_attributes_mask, actual_session_attributes_mask,
        "SessionAttributes builder did not produce the expected session attributes mask value"
    )
}
