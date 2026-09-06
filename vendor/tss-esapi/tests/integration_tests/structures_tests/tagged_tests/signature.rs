// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{structures::Signature, tss2_esys::TPMT_SIGNATURE};

#[test]
fn marshall_unmarshall() {
    crate::common::signatures()
        .iter()
        .for_each(crate::common::check_marshall_unmarshall);
}

#[test]
fn tpmt_conversion() {
    crate::common::signatures().iter().for_each(|signature| {
        let signature = signature.clone();
        let tpmt = TPMT_SIGNATURE::try_from(signature.clone())
            .expect("Failed conversion to TPMT_SIGNATURE");
        assert_eq!(
            signature,
            Signature::try_from(tpmt).expect("Failed conversion from TPMT_SIGNATURE")
        );
    });
}
