// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    structures::{Sensitive, SensitiveBuffer},
    Error, WrapperErrorKind,
};

const SENSITIVE_BUFFER_MAX_SIZE: usize = 1416;

#[test]
fn test_max_sized_data() {
    let _ = SensitiveBuffer::try_from(vec![0xffu8; SENSITIVE_BUFFER_MAX_SIZE])
        .expect("Failed to parse buffer of maximum size as SensitiveBuffer");
}

#[test]
fn test_to_large_data() {
    assert_eq!(
        SensitiveBuffer::try_from(vec![0xffu8; SENSITIVE_BUFFER_MAX_SIZE + 1])
            .expect_err("Converting a buffer that is to large did not produce an error"),
        Error::WrapperError(WrapperErrorKind::WrongParamSize),
        "Wrong kind of error when converting a buffer with size {} to SensitiveBuffer",
        SENSITIVE_BUFFER_MAX_SIZE + 1
    );
}

#[test]
fn marshall_unmarshall() {
    crate::common::sensitives().iter().for_each(|sensitive| {
        let sensitive = sensitive.clone();
        let pub_buf = SensitiveBuffer::try_from(sensitive.clone())
            .expect("Failed to convert from Sensitive to SensitiveBuffer");
        crate::common::check_marshall_unmarshall(&pub_buf);
        assert_eq!(
            sensitive,
            Sensitive::try_from(pub_buf)
                .expect("Failed to convert from SensitiveBuffer to Sensitive")
        );
    });
}
