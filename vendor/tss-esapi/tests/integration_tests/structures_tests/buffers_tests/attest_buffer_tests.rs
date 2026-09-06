// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{structures::AttestBuffer, tss2_esys::TPM2B_ATTEST, Error, WrapperErrorKind};

const ATTEST_BUFFER_MAX_SIZE: usize = 2304;

#[test]
fn test_max_sized_data() {
    let _ = AttestBuffer::try_from(vec![0xFFu8; ATTEST_BUFFER_MAX_SIZE])
        .expect("Failed to parse buffer if maximum size as AttestBuffer");
}

#[test]
fn test_to_large_data() {
    assert_eq!(
        AttestBuffer::try_from(vec![0xFFu8; ATTEST_BUFFER_MAX_SIZE + 1])
            .expect_err("Converting a buffer that is to large did not produce an error"),
        Error::WrapperError(WrapperErrorKind::WrongParamSize),
        "Wrong kind of error when converting a buffer with size {} to AttestBuffer",
        ATTEST_BUFFER_MAX_SIZE + 1
    );
}

#[test]
fn test_default() {
    {
        let attest_buffer: AttestBuffer = Default::default();
        let expected: TPM2B_ATTEST = Default::default();
        let actual = TPM2B_ATTEST::from(attest_buffer);
        assert_eq!(expected.size, actual.size);
        assert_eq!(
            expected.attestationData.len(),
            actual.attestationData.len(),
            "Native and TSS attest buffer don't have the same length"
        );
        assert!(
            expected
                .attestationData
                .iter()
                .zip(actual.attestationData.iter())
                .all(|(a, b)| a == b),
            "Native and TSS attest buffer is not equal"
        );
    }
    {
        let tss_attest_buffer: TPM2B_ATTEST = Default::default();
        let expected: AttestBuffer = Default::default();
        let actual = AttestBuffer::try_from(tss_attest_buffer).unwrap();
        assert_eq!(expected, actual);
    }
}
