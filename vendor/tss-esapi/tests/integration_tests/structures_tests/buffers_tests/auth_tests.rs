// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::structures::Auth;
use tss_esapi::tss2_esys::TPM2B_AUTH;
// The TPM2B_AUTH is currently
// just a typedef in the C code which results
// in it being just a type alias for TPM2B_DIGEST
// in the rust code. So the same size restrictions that
// TPM2B_DIGEST have will apply here as well.
mod test_auth {
    use super::*;

    #[test]
    fn test_max_sized_data() {
        let _ = Auth::try_from([0xff; 64].to_vec()).unwrap();
    }

    #[test]
    fn test_to_large_data() {
        // Removed:
        //    - test_handle_auth::test_set_large_handle
        //    - test_create::test_long_auth_create
        //    - test_create_primary::test_long_auth_create_primary
        // from the context tests and put here instead.

        let _ = Auth::try_from([0xff; 100].to_vec()).unwrap_err();
    }

    #[test]
    fn test_default() {
        {
            let auth: Auth = Default::default();
            let expected: TPM2B_AUTH = Default::default();
            let actual = TPM2B_AUTH::from(auth);
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
            let tss_auth: TPM2B_AUTH = Default::default();
            let expected: Auth = Default::default();
            let actual = Auth::try_from(tss_auth).unwrap();
            assert_eq!(expected, actual);
        }
    }
}
