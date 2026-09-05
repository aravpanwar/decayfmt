// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    structures::{Sensitive, SensitiveBuffer},
    tss2_esys::TPM2B_SENSITIVE,
};

#[test]
fn marshall_unmarshall() {
    crate::common::sensitives()
        .iter()
        .for_each(crate::common::check_marshall_unmarshall);
}

#[test]
fn tpm2b_conversion() {
    crate::common::sensitives().iter().for_each(|sensitive| {
        let sensitive = sensitive.clone();
        let tpm2b = TPM2B_SENSITIVE::try_from(sensitive.clone())
            .expect("Failed to convert from Sensitive to TPM2B_SENSITIVE");
        let buf = SensitiveBuffer::try_from(sensitive.clone())
            .expect("Failed to convert from Sensitive to SensitiveBuffer");
        assert_eq!(
            buf,
            SensitiveBuffer::try_from(tpm2b)
                .expect("Failed to convert from SensitiveBuffer to TPM2B_SENSITIVE")
        );
        assert_eq!(
            sensitive,
            Sensitive::try_from(buf).expect("Failed to convert from SensitiveBuffer to Sensitive")
        );
        assert_eq!(
            sensitive,
            Sensitive::try_from(tpm2b)
                .expect("Failed to convert from TPM2B_SENSITIVE to Sensitive")
        )
    });
}
