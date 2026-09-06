// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::tss2_esys::TPMA_CC;

pub fn ensure_tpma_cc_equality(expected: &TPMA_CC, actual: &TPMA_CC) {
    assert_eq!(
        expected, actual,
        "mismatch between actual and expected TPMA_CC value"
    );
}
