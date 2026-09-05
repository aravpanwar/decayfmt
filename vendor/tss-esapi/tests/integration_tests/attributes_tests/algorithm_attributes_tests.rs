// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Shl;

use tss_esapi::{attributes::AlgorithmAttributes, tss2_esys::TPMA_ALGORITHM};

#[test]
fn test_conversions() {
    let expected_tpma_algorithm: TPMA_ALGORITHM = 0x16;
    let expected_algorithm_attributes = AlgorithmAttributes(expected_tpma_algorithm);
    let actual_algorithm_attributes: AlgorithmAttributes = expected_tpma_algorithm.into();
    let actual_tpma_algorithm: TPMA_ALGORITHM = expected_algorithm_attributes.into();

    assert_eq!(
        expected_algorithm_attributes, actual_algorithm_attributes,
        "AlgorithmAttributes converted from TPMA_ALGORITHM did not contain expected value"
    );

    assert_eq!(
        expected_tpma_algorithm, actual_tpma_algorithm,
        "TPMA_ALGORITHM converted from AlgorithmAttributes did not contain expected value"
    );
}

#[test]
fn test_all_set() {
    let attributes = AlgorithmAttributes::from(0xFFFFFFFF);
    assert!(
        attributes.asymmetric(),
        "'asymmetric' is unexpectedly not set"
    );
    assert!(
        attributes.symmetric(),
        "'symmetric' is unexpectedly not set"
    );
    assert!(attributes.hash(), "'hash' is unexpectedly not set");
    assert!(attributes.object(), "'object' is unexpectedly not set");
    assert!(attributes.signing(), "'signing' is unexpectedly not set");
    assert!(
        attributes.encrypting(),
        "'encrypting' is unexpectedly not set"
    );
    assert!(attributes.method(), "'method' is unexpectedly not set");
}

#[test]
fn test_none_set() {
    let attributes = AlgorithmAttributes::from(0x0);
    assert!(!attributes.asymmetric(), "'asymmetric' is unexpectedly set");
    assert!(!attributes.symmetric(), "'symmetric' is unexpectedly set");
    assert!(!attributes.hash(), "'hash' is unexpectedly set");
    assert!(!attributes.object(), "'object' is unexpectedly set");
    assert!(!attributes.signing(), "'signing' is unexpectedly set");
    assert!(!attributes.encrypting(), "'encrypting' is unexpectedly set");
    assert!(!attributes.method(), "'method' is unexpectedly set");
}

#[test]
fn test_asymmetric_set() {
    let attributes = AlgorithmAttributes::from(1u32.shl(0));
    assert!(
        attributes.asymmetric(),
        "'asymmetric' is unexpectedly not set"
    );
    assert!(!attributes.symmetric(), "'symmetric' is unexpectedly set");
    assert!(!attributes.hash(), "'hash' is unexpectedly set");
    assert!(!attributes.object(), "'object' is unexpectedly set");
    assert!(!attributes.signing(), "'signing' is unexpectedly set");
    assert!(!attributes.encrypting(), "'encrypting' is unexpectedly set");
    assert!(!attributes.method(), "'method' is unexpectedly set");
}

#[test]
fn test_symmetric_set() {
    let attributes = AlgorithmAttributes::from(1u32.shl(1));
    assert!(!attributes.asymmetric(), "'asymmetric' is unexpectedly set");
    assert!(
        attributes.symmetric(),
        "'symmetric' is unexpectedly not set"
    );
    assert!(!attributes.hash(), "'hash' is unexpectedly set");
    assert!(!attributes.object(), "'object' is unexpectedly set");
    assert!(!attributes.signing(), "'signing' is unexpectedly set");
    assert!(!attributes.encrypting(), "'encrypting' is unexpectedly set");
    assert!(!attributes.method(), "'method' is unexpectedly set");
}

#[test]
fn test_hash_set() {
    let attributes = AlgorithmAttributes::from(1u32.shl(2));
    assert!(!attributes.asymmetric(), "'asymmetric' is unexpectedly set");
    assert!(!attributes.symmetric(), "'symmetric' is unexpectedly set");
    assert!(attributes.hash(), "'hash' is unexpectedly not set");
    assert!(!attributes.object(), "'object' is unexpectedly set");
    assert!(!attributes.signing(), "'signing' is unexpectedly set");
    assert!(!attributes.encrypting(), "'encrypting' is unexpectedly set");
    assert!(!attributes.method(), "'method' is unexpectedly set");
}

#[test]
fn test_object_set() {
    let attributes = AlgorithmAttributes::from(1u32.shl(3));
    assert!(!attributes.asymmetric(), "'asymmetric' is unexpectedly set");
    assert!(!attributes.symmetric(), "'symmetric' is unexpectedly set");
    assert!(!attributes.hash(), "'hash' is unexpectedly set");
    assert!(attributes.object(), "'object' is unexpectedly not set");
    assert!(!attributes.signing(), "'signing' is unexpectedly set");
    assert!(!attributes.encrypting(), "'encrypting' is unexpectedly set");
    assert!(!attributes.method(), "'method' is unexpectedly set");
}

#[test]
fn test_signing_set() {
    let attributes = AlgorithmAttributes::from(1u32.shl(8));
    assert!(!attributes.asymmetric(), "'asymmetric' is unexpectedly set");
    assert!(!attributes.symmetric(), "'symmetric' is unexpectedly set");
    assert!(!attributes.hash(), "'hash' is unexpectedly set");
    assert!(!attributes.object(), "'object' is unexpectedly set");
    assert!(attributes.signing(), "'signing' is unexpectedly not set");
    assert!(!attributes.encrypting(), "'encrypting' is unexpectedly set");
    assert!(!attributes.method(), "'method' is unexpectedly set");
}

#[test]
fn test_encrypting_set() {
    let attributes = AlgorithmAttributes::from(1u32.shl(9));
    assert!(!attributes.asymmetric(), "'asymmetric' is unexpectedly set");
    assert!(!attributes.symmetric(), "'symmetric' is unexpectedly set");
    assert!(!attributes.hash(), "'hash' is unexpectedly set");
    assert!(!attributes.object(), "'object' is unexpectedly set");
    assert!(!attributes.signing(), "'signing' is unexpectedly set");
    assert!(
        attributes.encrypting(),
        "'encrypting' is unexpectedly not set"
    );
    assert!(!attributes.method(), "'method' is unexpectedly set");
}

#[test]
fn test_method_set() {
    let attributes = AlgorithmAttributes::from(1u32.shl(10));
    assert!(!attributes.asymmetric(), "'asymmetric' is unexpectedly set");
    assert!(!attributes.symmetric(), "'symmetric' is unexpectedly set");
    assert!(!attributes.hash(), "'hash' is unexpectedly set");
    assert!(!attributes.object(), "'object' is unexpectedly set");
    assert!(!attributes.signing(), "'signing' is unexpectedly set");
    assert!(!attributes.encrypting(), "'encrypting' is unexpectedly set");
    assert!(attributes.method(), "'method' is unexpectedly not set");
}
