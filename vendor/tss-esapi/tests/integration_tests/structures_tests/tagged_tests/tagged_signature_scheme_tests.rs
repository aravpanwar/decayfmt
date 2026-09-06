// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    interface_types::algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
    structures::{EcDaaScheme, HashScheme, HmacScheme, SignatureScheme},
    tss2_esys::{
        TPMS_SCHEME_ECDAA, TPMS_SCHEME_HASH, TPMS_SCHEME_HMAC, TPMT_SIG_SCHEME, TPMU_SIG_SCHEME,
    },
    Error, WrapperErrorKind,
};

use std::convert::{TryFrom, TryInto};

fn validate_tss_hash_scheme(
    left: &TPMS_SCHEME_HASH,
    right: &TPMS_SCHEME_HASH,
    union_field_name: &str,
) {
    assert_eq!(
        left.hashAlg, right.hashAlg,
        "{} in details, hashAlg did not match",
        union_field_name
    );
}

fn validate_tss_ecdaa_scheme(
    left: &TPMS_SCHEME_ECDAA,
    right: &TPMS_SCHEME_ECDAA,
    union_field_name: &str,
) {
    assert_eq!(
        left.hashAlg, right.hashAlg,
        "{} in details, hashAlg did not match",
        union_field_name
    );
    assert_eq!(
        left.count, right.count,
        "{} in details, count did not match",
        union_field_name
    );
}

fn validate_tss_hmac_scheme(
    left: &TPMS_SCHEME_HMAC,
    right: &TPMS_SCHEME_HMAC,
    union_field_name: &str,
) {
    assert_eq!(
        left.hashAlg, right.hashAlg,
        "{} in details, hashAlg did not match",
        union_field_name
    );
}

macro_rules! test_valid_conversions_generic {
    (SignatureScheme::$item:ident, $union_field_name:ident, $tss_details_field_validator:expr, $native_scheme_field:ident, $native_scheme:expr) => {
        let tss_actual: TPMT_SIG_SCHEME = SignatureScheme::$item { $native_scheme_field: $native_scheme }
        .try_into()
        .expect(&format!("Failed to convert {} signature scheem into TSS type", stringify!($item)));


        let tss_expected = TPMT_SIG_SCHEME {
            scheme: SignatureSchemeAlgorithm::$item.into(),
            details: TPMU_SIG_SCHEME {
                $union_field_name: $native_scheme.into(),
            },
        };

        assert_eq!(
            tss_actual.scheme, tss_expected.scheme,
            "scheme for Actual converted value did not match expected in TSS types for SignatureScheme {}", stringify!($item),
        );

        $tss_details_field_validator(
            &unsafe { tss_actual.details.$union_field_name },
            &unsafe { tss_expected.details.$union_field_name },
            stringify!($union_field_name),
        );

        let native_expected = SignatureScheme::$item { $native_scheme_field: $native_scheme };

        let native_actual = SignatureScheme::try_from(tss_expected)
            .expect(&format!("Failed to convert TSS type into {}", stringify!($item)));

        assert_eq!(
            native_actual, native_expected,
            "The actual SignatureScheme did not match expected",
        );
    };
    // For a selector that has no data
    (SignatureScheme::$item:ident) => {
        let tss_actual: TPMT_SIG_SCHEME = SignatureScheme::$item
        .try_into()
        .expect(&format!("Failed to convert {} signature scheem into TSS type", stringify!($item)));

        let tss_expected = TPMT_SIG_SCHEME {
            scheme: SignatureSchemeAlgorithm::$item.into(),
            details: Default::default(),
        };

        assert_eq!(
            tss_actual.scheme, tss_expected.scheme,
            "scheme for Actual converted value did not match expected in TSS types for SignatureScheme {}", stringify!($item),
        );

        let native_expected = SignatureScheme::$item;
        let native_actual = SignatureScheme::try_from(tss_expected)
            .expect(&format!("Failed to convert TSS type into {}", stringify!($item)));

        assert_eq!(
            native_actual, native_expected,
            "The actual SignatureScheme did not match expected",
        );
    };
}

macro_rules! test_valid_conversions {
    (SignatureScheme::EcDaa, $union_field_name:ident) => {
        test_valid_conversions_generic!(
            SignatureScheme::EcDaa,
            $union_field_name,
            validate_tss_ecdaa_scheme,
            ecdaa_scheme,
            EcDaaScheme::new(HashingAlgorithm::Sha256, 1)
        );
    };
    (SignatureScheme::Hmac, $union_field_name:ident) => {
        test_valid_conversions_generic!(
            SignatureScheme::Hmac,
            $union_field_name,
            validate_tss_hmac_scheme,
            hmac_scheme,
            HmacScheme::new(HashingAlgorithm::Sha256)
        );
    };
    (SignatureScheme::$item:ident, $union_field_name:ident) => {
        test_valid_conversions_generic!(
            SignatureScheme::$item,
            $union_field_name,
            validate_tss_hash_scheme,
            hash_scheme,
            HashScheme::new(HashingAlgorithm::Sha256)
        );
    };
    (SignatureScheme::Null) => {
        test_valid_conversions_generic!(SignatureScheme::Null);
    };
}

#[test]
fn test_conversions() {
    test_valid_conversions!(SignatureScheme::RsaSsa, rsassa);
    test_valid_conversions!(SignatureScheme::RsaPss, rsapss);
    test_valid_conversions!(SignatureScheme::EcDsa, ecdsa);
    test_valid_conversions!(SignatureScheme::Sm2, sm2);
    test_valid_conversions!(SignatureScheme::EcSchnorr, ecschnorr);
    test_valid_conversions!(SignatureScheme::EcDaa, ecdaa);
    test_valid_conversions!(SignatureScheme::Hmac, hmac);
    test_valid_conversions!(SignatureScheme::Null);
}

#[test]
fn test_valid_any_sig() {
    let mut signature_scheme = SignatureScheme::RsaPss {
        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
    };
    assert_eq!(
        HashingAlgorithm::Sha256,
        signature_scheme
            .signing_scheme()
            .expect("Failed to get signing scheme digest"),
        "The signing scheme method did not return the correct value"
    );

    signature_scheme
        .set_signing_scheme(HashingAlgorithm::Sha384)
        .expect("Failed to change signing scheme digest");

    assert_eq!(
        HashingAlgorithm::Sha384,
        signature_scheme
            .signing_scheme()
            .expect("Failed to get signing key digest"),
        "The signing scheme method did not return the correct value after change."
    );
}

#[test]
fn test_invalid_any_sig() {
    let mut signature_scheme = SignatureScheme::Null;
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        signature_scheme.signing_scheme(),
        "Trying to get signing scheme digest from a non signing SignatureScheme did not produce the expected error",
    );

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        signature_scheme.set_signing_scheme(HashingAlgorithm::Sha256),
        "Trying to set signing scheme digest on a non signing SignatureScheme did not produce the expected error",
    )
}
