// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::structures::RsaExponent;

#[test]
fn rsa_exponent_value_test() {
    let expected_value = 97;

    let rsa_exponent = RsaExponent::create(expected_value).unwrap_or_else(|_| {
        panic!(
            "Failed to create a RsaExponent from the value {}",
            expected_value
        )
    });

    assert_eq!(expected_value, rsa_exponent.value());
}
