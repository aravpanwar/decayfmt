// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::{convert::TryFrom, ops::Deref};
use tss_esapi::{
    structures::{Auth, SensitiveCreate, SensitiveCreateBuffer, SensitiveData},
    tss2_esys::TPM2B_SENSITIVE_CREATE,
    Error, WrapperErrorKind,
};

// TPM2B_AUTH = TPM2B_DIGEST = u16 + [u8;64] = 2 + 64 = 66
// TPM2B_SENSITIVE_DATA = u16 + [u8; 256] = 2 + 256 = 258
// TPMS_SENSITIVE_CREATE = TPM2B_AUTH + TPM2B_SENSITIVE_DATA = std::mem::size_of::<TPMS_SENSITIVE_CREATE>() = 324
const SENSITIVE_CREATE_BUFFER_MAX_SIZE: usize = 324;

#[test]
fn test_byte_conversions() {
    let expected_buffer = vec![0xFFu8; SENSITIVE_CREATE_BUFFER_MAX_SIZE];
    let sensitive_create_buffer_from_slice =
        SensitiveCreateBuffer::try_from(expected_buffer.as_slice())
            .expect("Failed to create SensitiveCreateBuffer from byte slice");
    assert_eq!(
        &expected_buffer,
        sensitive_create_buffer_from_slice.value(),
        "SensitiveCreateBuffer converted from slice did not produce the expected value"
    );
    let sensitive_create_buffer_from_vec = SensitiveCreateBuffer::try_from(expected_buffer.clone())
        .expect("Failed to create SensitiveCreateBuffer from byte slice");
    assert_eq!(
        &expected_buffer,
        sensitive_create_buffer_from_vec.value(),
        "SensitiveCreateBuffer converted from Vec did not produce the expected value"
    );
}

#[test]
fn test_conversions_of_over_sized_byte_data() {
    let over_sized_buffer = vec![0xFFu8; SENSITIVE_CREATE_BUFFER_MAX_SIZE + 1];

    assert_eq!(
        SensitiveCreateBuffer::try_from(over_sized_buffer.as_slice())
            .expect_err("Converting a slice that is to large did not produce an error"),
        Error::WrapperError(WrapperErrorKind::WrongParamSize),
        "Wrong kind of error when converting a slice with size {} to SensitiveCreateBuffer",
        SENSITIVE_CREATE_BUFFER_MAX_SIZE + 1
    );

    assert_eq!(
        SensitiveCreateBuffer::try_from(over_sized_buffer)
            .expect_err("Converting a Vec that is to large did not produce an error"),
        Error::WrapperError(WrapperErrorKind::WrongParamSize),
        "Wrong kind of error when converting a Vec with size {} to SensitiveCreateBuffer",
        SENSITIVE_CREATE_BUFFER_MAX_SIZE + 1
    );
}

#[test]
fn test_deref() {
    let expected_buffer = vec![0x0fu8; SENSITIVE_CREATE_BUFFER_MAX_SIZE];
    let sensitive_create_buffer_from_slice =
        SensitiveCreateBuffer::try_from(expected_buffer.as_slice())
            .expect("Failed to create SensitiveCreateBuffer from byte slice");
    assert_eq!(
        &expected_buffer,
        sensitive_create_buffer_from_slice.deref(),
        "Calling deref() on a SensitiveCreateBuffer converted from slice did not produce the expected value"
    );
    let sensitive_create_buffer_from_vec = SensitiveCreateBuffer::try_from(expected_buffer.clone())
        .expect("Failed to create SensitiveCreateBuffer from byte slice");
    assert_eq!(
        &expected_buffer,
        sensitive_create_buffer_from_vec.deref(),
        "Calling deref() on a SensitiveCreateBuffer converted from Vec did not produce the expected value"
    );
}

#[test]
fn test_tpm_types_conversions() {
    let expected_auth = Auth::default();
    let expected_sensitive_data = SensitiveData::default();
    let expected_sensitive_create = SensitiveCreate::new(expected_auth, expected_sensitive_data);
    let expected_tpm2b_sensitive_create = TPM2B_SENSITIVE_CREATE {
        size: 2 + 2, // both auth and sensitive data is empty so only the size parameters contributes.
        sensitive: expected_sensitive_create.clone().into(),
    };
    let actual_sensitive_create_buffer =
        SensitiveCreateBuffer::try_from(expected_tpm2b_sensitive_create)
            .expect("Failed to create SensitiveCreateBuffer from TPM2B_SENSITIVE_CREATE");
    assert_eq!(
        actual_sensitive_create_buffer.value().len(),
        2 + 2,
        "Unexpected size of the SensitiveCreateBuffer"
    );
    let actual_sensitive_create = SensitiveCreate::try_from(actual_sensitive_create_buffer.clone())
        .expect("Failed to create SensitiveCreate from SensitiveCreateBuffer");
    assert_eq!(
        expected_sensitive_create, actual_sensitive_create,
        "SensitiveCreate converted from SensitiveCreateBuffer did not contain expected values."
    );
    let actual_tpm2b_sensitive_create_buffer =
        TPM2B_SENSITIVE_CREATE::try_from(actual_sensitive_create_buffer)
            .expect("Failed to create TPM2B_SENSITIVE_CREATE from SensitiveCreateBuffer");
    crate::common::ensure_tpm2b_sensitive_create_equality(
        &expected_tpm2b_sensitive_create,
        &actual_tpm2b_sensitive_create_buffer,
    );
}

#[test]
fn test_marshall_unmarshall() {
    let expected_auth =
        Auth::try_from(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).expect("Failed to create auth value");
    let expected_sensitive_data =
        SensitiveData::try_from(vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19])
            .expect("Failed to create sensitive data");
    let expected_sensitive_create = SensitiveCreate::new(expected_auth, expected_sensitive_data);
    let expected_sensitive_create_buffer =
        SensitiveCreateBuffer::try_from(expected_sensitive_create.clone())
            .expect("Failed to create SensitiveCreateBuffer");
    crate::common::check_marshall_unmarshall(&expected_sensitive_create_buffer);
    assert_eq!(
        expected_sensitive_create,
        SensitiveCreate::try_from(expected_sensitive_create_buffer)
            .expect("Failed to convert from SensitiveCreateBuffer to SensitiveCreate"),
        "SensitiveCreate converted from SensitiveCreateBuffer did not contain the expected values"
    );
}
