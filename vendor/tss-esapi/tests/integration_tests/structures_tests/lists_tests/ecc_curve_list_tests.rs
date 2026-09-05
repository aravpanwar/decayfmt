// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::ecc::EccCurveIdentifier,
    structures::EccCurveList,
    tss2_esys::{TPM2_ECC_CURVE, TPML_ECC_CURVE},
    Error, WrapperErrorKind,
};

#[test]
fn test_conversions() {
    let expected_ecc_curves: Vec<EccCurveIdentifier> = vec![];
    let mut ecc_curve_list = EccCurveList::new();
    for curve in expected_ecc_curves.iter() {
        ecc_curve_list
            .add(*curve)
            .expect("Failed to add curve to list");
    }

    assert_eq!(expected_ecc_curves.len(), ecc_curve_list.len());

    expected_ecc_curves
        .iter()
        .zip(ecc_curve_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual,
                "The created ECC curve list did not contain the expected values"
            );
        });

    let tpml_ecc_curve = TPML_ECC_CURVE::from(ecc_curve_list);
    assert_eq!(
        expected_ecc_curves.len(),
        tpml_ecc_curve.count as usize,
        "The number of ecc_curves in the TPML_ECC_CURVE is different than expected"
    );

    expected_ecc_curves
        .iter()
        .zip(tpml_ecc_curve.eccCurves[..expected_ecc_curves.len()].iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                TPM2_ECC_CURVE::from(*expected),
                *actual,
                "Got mismatch between expected FFI ECC curve and actual ECC curve"
            )
        });

    let ecc_curve_list =
        EccCurveList::try_from(tpml_ecc_curve).expect("Failed to convert from TPML_ECC_CURVE");

    assert_eq!(
        expected_ecc_curves.len(),
        ecc_curve_list.len(),
        "Converted ECC curve list has a different length"
    );

    expected_ecc_curves
        .iter()
        .zip(ecc_curve_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual,
                "The converted ECC curve list did not contain the expected values"
            );
        });
}

#[test]
fn test_vector_conversion() {
    let expected_ecc_curves: Vec<EccCurveIdentifier> = vec![
        EccCurveIdentifier::NistP256,
        EccCurveIdentifier::NistP192,
        EccCurveIdentifier::NistP384,
    ];

    let ecc_curve_list =
        EccCurveList::try_from(expected_ecc_curves.clone()).expect("Failed to convert from vector");

    expected_ecc_curves
        .iter()
        .zip(ecc_curve_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual,
                "The converted curve list did not contain the expected values"
            );
        });

    let converted_ecc_curves = Vec::<EccCurveIdentifier>::from(ecc_curve_list);

    assert_eq!(
        expected_ecc_curves, converted_ecc_curves,
        "Converted vector did not match initial vector"
    );
}

#[test]
fn test_add_too_many() {
    let mut ecc_curve_list = EccCurveList::new();
    for _ in 0..EccCurveList::MAX_SIZE {
        ecc_curve_list
            .add(EccCurveIdentifier::NistP256)
            .expect("Failed to add the maximum amount of ECC curves");
    }

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::WrongParamSize)),
        ecc_curve_list.add(EccCurveIdentifier::NistP256),
        "Added more ECC curves than should've been possible"
    );
}

#[test]
fn test_invalid_size_tpml() {
    let tpml = TPML_ECC_CURVE {
        count: (EccCurveList::MAX_SIZE + 1) as u32,
        eccCurves: [0; 508],
    };

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        EccCurveList::try_from(tpml),
        "Converting from TPML_ECC_CURVE did not produce the expected failure"
    );
}

#[test]
fn test_invalid_size_vec() {
    let vec = vec![EccCurveIdentifier::NistP256; EccCurveList::MAX_SIZE + 1];

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        EccCurveList::try_from(vec),
        "Converting from vector of curves did not produce the expected failure"
    );
}
