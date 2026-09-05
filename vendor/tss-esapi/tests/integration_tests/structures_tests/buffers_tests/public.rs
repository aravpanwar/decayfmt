// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    structures::{Public, PublicBuffer},
    Error, WrapperErrorKind,
};

const PUBLIC_BUFFER_MAX_SIZE: usize = 612;

#[test]
fn test_max_sized_data() {
    let _ = PublicBuffer::try_from(vec![0xffu8; PUBLIC_BUFFER_MAX_SIZE])
        .expect("Failed to parse buffer of maximum size as PublicBuffer");
}

#[test]
fn test_to_large_data() {
    assert_eq!(
        PublicBuffer::try_from(vec![0xffu8; PUBLIC_BUFFER_MAX_SIZE + 1])
            .expect_err("Converting a buffer that is to large did not produce an error"),
        Error::WrapperError(WrapperErrorKind::WrongParamSize),
        "Wrong kind of error when converting a buffer with size {} to PublicBuffer",
        PUBLIC_BUFFER_MAX_SIZE + 1
    );
}

#[test]
fn marshall_unmarshall() {
    crate::common::publics().iter().for_each(|public| {
        let public = public.clone();
        let pub_buf = PublicBuffer::try_from(public.clone())
            .expect("Failed to convert from Public to PublicBuffer");
        crate::common::check_marshall_unmarshall(&pub_buf);
        assert_eq!(
            public,
            Public::try_from(pub_buf).expect("Failed to convert from PublicBuffer to Public")
        );
    });
}
