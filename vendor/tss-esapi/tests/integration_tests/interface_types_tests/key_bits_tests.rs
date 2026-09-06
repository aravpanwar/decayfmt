// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

macro_rules! test_conversions {
    ($tss_ket_bits_interface_type:ident, $value:tt, $interface_type:ident::$interface_type_item:ident) => {
        assert_eq!(
            $value as $tss_ket_bits_interface_type,
            $interface_type::$interface_type_item.into()
        );
        assert_eq!(
            $interface_type::try_from($value as $tss_ket_bits_interface_type).expect(&format!(
                "Failed to parse from a value {}",
                $value as $tss_ket_bits_interface_type
            )),
            $interface_type::$interface_type_item,
        );
    };
}

macro_rules! test_invalid_conversions {
    ($tss_ket_bits_interface_type:ident, $value:tt, $interface_type:ident, WrapperErrorKind::$expected_error:ident) => {
        assert_eq!(
            $interface_type::try_from($value as $tss_ket_bits_interface_type),
            Err(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::$expected_error
            )),
        );
    };
}

mod aes_key_bits_tests {
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::key_bits::AesKeyBits, tss2_esys::TPMI_AES_KEY_BITS};

    #[test]
    fn test_valid_conversions() {
        test_conversions!(TPMI_AES_KEY_BITS, 128, AesKeyBits::Aes128);
        test_conversions!(TPMI_AES_KEY_BITS, 192, AesKeyBits::Aes192);
        test_conversions!(TPMI_AES_KEY_BITS, 256, AesKeyBits::Aes256);
    }

    #[test]
    fn test_invalid_conversions() {
        test_invalid_conversions!(
            TPMI_AES_KEY_BITS,
            0,
            AesKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_AES_KEY_BITS,
            129,
            AesKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_AES_KEY_BITS,
            193,
            AesKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_AES_KEY_BITS,
            257,
            AesKeyBits,
            WrapperErrorKind::InvalidParam
        );
    }
}

mod sm4_key_bits_tests {
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::key_bits::Sm4KeyBits, tss2_esys::TPMI_SM4_KEY_BITS};

    #[test]
    fn test_valid_conversions() {
        test_conversions!(TPMI_SM4_KEY_BITS, 128, Sm4KeyBits::Sm4_128);
    }

    #[test]
    fn test_invalid_conversions() {
        test_invalid_conversions!(
            TPMI_SM4_KEY_BITS,
            0,
            Sm4KeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_SM4_KEY_BITS,
            129,
            Sm4KeyBits,
            WrapperErrorKind::InvalidParam
        );
    }
}

mod camellia_key_bits_tests {
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::key_bits::CamelliaKeyBits, tss2_esys::TPM2_KEY_BITS};

    #[test]
    fn test_valid_conversions() {
        test_conversions!(TPM2_KEY_BITS, 128, CamelliaKeyBits::Camellia128);
        test_conversions!(TPM2_KEY_BITS, 192, CamelliaKeyBits::Camellia192);
        test_conversions!(TPM2_KEY_BITS, 256, CamelliaKeyBits::Camellia256);
    }

    #[test]
    fn test_invalid_conversions() {
        test_invalid_conversions!(
            TPM2_KEY_BITS,
            0,
            CamelliaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPM2_KEY_BITS,
            129,
            CamelliaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPM2_KEY_BITS,
            193,
            CamelliaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPM2_KEY_BITS,
            257,
            CamelliaKeyBits,
            WrapperErrorKind::InvalidParam
        );
    }
}

mod rsa_key_bits_tests {
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::key_bits::RsaKeyBits, tss2_esys::TPMI_RSA_KEY_BITS};

    #[test]
    fn test_valid_conversions() {
        test_conversions!(TPMI_RSA_KEY_BITS, 1024, RsaKeyBits::Rsa1024);
        test_conversions!(TPMI_RSA_KEY_BITS, 2048, RsaKeyBits::Rsa2048);
        test_conversions!(TPMI_RSA_KEY_BITS, 3072, RsaKeyBits::Rsa3072);
        test_conversions!(TPMI_RSA_KEY_BITS, 4096, RsaKeyBits::Rsa4096);
    }

    #[test]
    fn test_invalid_conversions() {
        test_invalid_conversions!(
            TPMI_RSA_KEY_BITS,
            0,
            RsaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_RSA_KEY_BITS,
            1025,
            RsaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_RSA_KEY_BITS,
            2049,
            RsaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_RSA_KEY_BITS,
            2073,
            RsaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_RSA_KEY_BITS,
            4097,
            RsaKeyBits,
            WrapperErrorKind::InvalidParam
        );
    }
}
