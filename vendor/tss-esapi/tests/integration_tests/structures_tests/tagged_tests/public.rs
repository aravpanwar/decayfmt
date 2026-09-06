// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    structures::{Public, PublicBuffer},
    tss2_esys::TPM2B_PUBLIC,
};

#[test]
fn marshall_unmarshall() {
    crate::common::publics()
        .iter()
        .for_each(crate::common::check_marshall_unmarshall);
}

#[test]
fn tpm2b_conversion() {
    crate::common::publics().iter().for_each(|public| {
        let public = public.clone();
        let tpm2b = TPM2B_PUBLIC::try_from(public.clone())
            .expect("Failed to convert from Public to TPM2B_PUBLIC");
        let buf = PublicBuffer::try_from(public.clone())
            .expect("Failed to convert from Public to PublicBuffer");
        assert_eq!(
            buf,
            PublicBuffer::try_from(tpm2b)
                .expect("Failed to convert from PublicBuffer to TPM2B_PUBLIC")
        );
        assert_eq!(
            public,
            Public::try_from(buf).expect("Failed to convert from PublicBuffer to Public")
        );
        assert_eq!(
            public,
            Public::try_from(tpm2b).expect("Failed to convert from TPM2B_PUBLIC to Public")
        )
    });
}
