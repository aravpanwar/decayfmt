// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::structures::Nonce;
use tss_esapi::tss2_esys::TPM2B_NONCE;
// The TPM2B_NONCE is currently
// just a typedef in the C code which results
// in it being just a type alias for TPM2B_DIGEST
// in the rust code. So the same size restrictions that
// TPM2B_DIGEST have will apply here as well.
#[test]
fn test_max_sized_data() {
    let _ = Nonce::try_from([0xff; 64].to_vec()).unwrap();
}

#[test]
fn test_to_large_data() {
    // Removed test_start_sess::test_long_nonce_sess
    // from context tests.

    let _ = Nonce::try_from(
        [
            231, 97, 201, 180, 0, 1, 185, 150, 85, 90, 174, 188, 105, 133, 188, 3, 206, 5, 222, 71,
            185, 1, 209, 243, 36, 130, 250, 116, 17, 0, 24, 4, 25, 225, 250, 198, 245, 210, 140,
            23, 139, 169, 15, 193, 4, 145, 52, 138, 149, 155, 238, 36, 74, 152, 179, 108, 200, 248,
            250, 100, 115, 214, 166, 165, 1, 27, 51, 11, 11, 244, 218, 157, 3, 174, 171, 142, 45,
            8, 9, 36, 202, 171, 165, 43, 208, 186, 232, 15, 241, 95, 81, 174, 189, 30, 213, 47, 86,
            115, 239, 49, 214, 235, 151, 9, 189, 174, 144, 238, 200, 201, 241, 157, 43, 37, 6, 96,
            94, 152, 159, 205, 54, 9, 181, 14, 35, 246, 49, 150, 163, 118, 242, 59, 54, 42, 221,
            215, 248, 23, 18, 223,
        ]
        .to_vec(),
    )
    .unwrap_err();
}
#[test]
fn test_default() {
    {
        let nonce: Nonce = Default::default();
        let expected: TPM2B_NONCE = Default::default();
        let actual = TPM2B_NONCE::from(nonce);
        assert_eq!(expected.size, actual.size);
        assert_eq!(
            expected.buffer.len(),
            actual.buffer.len(),
            "Buffers don't have the same length"
        );
        assert!(
            expected
                .buffer
                .iter()
                .zip(actual.buffer.iter())
                .all(|(a, b)| a == b),
            "Buffers are not equal"
        );
    }
    {
        let tss_nonce: TPM2B_NONCE = Default::default();
        let expected: Nonce = Default::default();
        let actual = Nonce::try_from(tss_nonce).unwrap();
        assert_eq!(expected, actual);
    }
}
