// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod public_rsa_test {
    use picky_asn1::wrapper::IntegerAsn1;
    use picky_asn1_x509::{AlgorithmIdentifier, PublicKey, SubjectPublicKeyInfo};
    use std::convert::TryFrom;
    use tss_esapi::{
        abstraction::public::DecodedKey,
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
            key_bits::RsaKeyBits,
        },
        structures::{Public, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme},
    };

    const RSA_KEY: [u8; 256] = [
        0xc9, 0x75, 0xf8, 0xb2, 0x30, 0xf4, 0x24, 0x6e, 0x95, 0xb1, 0x3c, 0x55, 0x0f, 0xe4, 0x48,
        0xe9, 0xac, 0x06, 0x1f, 0xa8, 0xbe, 0xa4, 0xd7, 0x1c, 0xa5, 0x5e, 0x2a, 0xbf, 0x60, 0xc2,
        0x98, 0x63, 0x6c, 0xb4, 0xe2, 0x61, 0x54, 0x31, 0xc3, 0x3e, 0x9d, 0x1a, 0x83, 0x84, 0x18,
        0x51, 0xe9, 0x8c, 0x24, 0xcf, 0xac, 0xc6, 0x0d, 0x26, 0x2c, 0x9f, 0x2b, 0xd5, 0x91, 0x98,
        0x89, 0xe3, 0x68, 0x97, 0x36, 0x02, 0xec, 0x16, 0x37, 0x24, 0x08, 0xb4, 0x77, 0xd1, 0x56,
        0x10, 0x3e, 0xf0, 0x64, 0xf6, 0x68, 0x50, 0x68, 0x31, 0xf8, 0x9b, 0x88, 0xf2, 0xc5, 0xfb,
        0xc9, 0x21, 0xd2, 0xdf, 0x93, 0x6f, 0x98, 0x94, 0x53, 0x68, 0xe5, 0x25, 0x8d, 0x8a, 0xf1,
        0xd7, 0x5b, 0xf3, 0xf9, 0xdf, 0x8c, 0x77, 0x24, 0x9e, 0x28, 0x09, 0x36, 0xf0, 0xa2, 0x93,
        0x17, 0xad, 0xbb, 0x1a, 0xd7, 0x6f, 0x25, 0x6b, 0x0c, 0xd3, 0x76, 0x7f, 0xcf, 0x3a, 0xe3,
        0x1a, 0x84, 0x57, 0x62, 0x71, 0x8a, 0x6a, 0x42, 0x94, 0x71, 0x21, 0x6a, 0x13, 0x73, 0x17,
        0x56, 0xa2, 0x38, 0xc1, 0x5e, 0x76, 0x0b, 0x67, 0x6b, 0x6e, 0xcd, 0xd3, 0xe2, 0x8a, 0x80,
        0x61, 0x6c, 0x1c, 0x60, 0x9d, 0x65, 0xbd, 0x5a, 0x4e, 0xeb, 0xa2, 0x06, 0xd6, 0xbe, 0xf5,
        0x49, 0xc1, 0x7d, 0xd9, 0x46, 0x3e, 0x9f, 0x2f, 0x92, 0xa4, 0x1a, 0x14, 0x2c, 0x1e, 0xb7,
        0x6d, 0x71, 0x29, 0x92, 0x43, 0x7b, 0x76, 0xa4, 0x8b, 0x33, 0xf3, 0xd0, 0xda, 0x7c, 0x7f,
        0x73, 0x50, 0xe2, 0xc5, 0x30, 0xad, 0x9e, 0x0f, 0x61, 0x73, 0xa0, 0xbb, 0x87, 0x1f, 0x0b,
        0x70, 0xa9, 0xa6, 0xaa, 0x31, 0x2d, 0x62, 0x2c, 0xaf, 0xea, 0x49, 0xb2, 0xce, 0x6c, 0x23,
        0x90, 0xdd, 0x29, 0x37, 0x67, 0xb1, 0xc9, 0x99, 0x3a, 0x3f, 0xa6, 0x69, 0xc9, 0x0d, 0x24,
        0x3f,
    ];

    pub fn get_ext_rsa_pub() -> Public {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build object attributes");

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new_unrestricted_signing_key(
                    RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                        .expect("Failed to create rsa scheme"),
                    RsaKeyBits::Rsa2048,
                    Default::default(), // Default exponent is 0 but TPM internally this is mapped to 65537
                )
                .build()
                .expect("Failed to create rsa parameters for public structure"),
            )
            .with_rsa_unique_identifier(
                PublicKeyRsa::try_from(&RSA_KEY[..])
                    .expect("Failed to create Public RSA key from buffer"),
            )
            .build()
            .expect("Failed to build Public structure")
    }

    #[test]
    fn test_public_to_decoded_key_rsa() {
        let public_rsa = get_ext_rsa_pub();
        let default_exponent = IntegerAsn1::from_bytes_be_signed(65537_u32.to_be_bytes().to_vec());
        let decoded_key = DecodedKey::try_from(public_rsa)
            .expect("Failed to convert Public structure to DecodedKey (RSA).");
        match decoded_key {
            DecodedKey::RsaPublicKey(key) => {
                assert_eq!(
                    key.public_exponent, default_exponent,
                    "RSA exponents are not equal."
                );
                assert_eq!(key.modulus.as_unsigned_bytes_be(), RSA_KEY);
            }
            DecodedKey::EcPoint(..) => panic!("RSA key was decoded to EcPoint!"),
        }
    }

    #[test]
    fn test_public_to_subject_public_key_info_rsa() {
        let public_rsa = get_ext_rsa_pub();
        let default_exponent = IntegerAsn1::from_bytes_be_signed(65537_u32.to_be_bytes().to_vec());
        let key = SubjectPublicKeyInfo::try_from(public_rsa)
            .expect("Failed to convert Public structure to SubjectPublicKeyInfo (RSA).");
        assert_eq!(key.algorithm, AlgorithmIdentifier::new_rsa_encryption());
        match key.subject_public_key {
            PublicKey::Rsa(key) => {
                assert_eq!(key.public_exponent, default_exponent);
                assert_eq!(key.modulus.as_unsigned_bytes_be(), RSA_KEY)
            }
            _ => panic!("PublicKey of SubjectPublicKeyInfo is not an instance for RSA"),
        }
    }
}

mod public_ecc_test {
    use picky_asn1::bit_string::BitString;
    use picky_asn1_x509::{AlgorithmIdentifier, EcParameters, PublicKey, SubjectPublicKeyInfo};
    use std::convert::TryFrom;
    use tss_esapi::{
        abstraction::public::DecodedKey,
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            ecc::EccCurve,
        },
        structures::{
            EccParameter, EccPoint, EccScheme, KeyDerivationFunctionScheme, Public, PublicBuilder,
            PublicEccParametersBuilder,
        },
    };

    const EC_POINT: [u8; 65] = [
        0x04, 0x14, 0xd8, 0x59, 0xec, 0x31, 0xe5, 0x94, 0x0f, 0x2b, 0x3a, 0x08, 0x97, 0x64, 0xc4,
        0xfb, 0xa6, 0xcd, 0xaf, 0x0e, 0xa2, 0x44, 0x7f, 0x30, 0xcf, 0xe8, 0x2e, 0xe5, 0x1b, 0x47,
        0x70, 0x01, 0xc3, 0xd6, 0xb4, 0x69, 0x7e, 0xa1, 0xcf, 0x03, 0xdb, 0x05, 0x9c, 0x62, 0x3e,
        0xc6, 0x15, 0x4f, 0xed, 0xab, 0xa0, 0xa0, 0xab, 0x84, 0x2e, 0x67, 0x0c, 0x98, 0xc7, 0x1e,
        0xef, 0xd2, 0x51, 0x91, 0xce,
    ];

    pub fn get_ecc_point() -> EccPoint {
        let x =
            EccParameter::try_from(&EC_POINT[1..33]).expect("Failed to construct x EccParameter");
        let y: EccParameter =
            EccParameter::try_from(&EC_POINT[33..]).expect("Failed to construct y EccParameter");
        EccPoint::new(x, y)
    }

    pub fn get_ext_ecc_pub() -> Public {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build object attributes");

        let ecc_parameters = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::Null)
            .with_curve(EccCurve::NistP256)
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(false)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build()
            .expect("Failed to build PublicEccParameters");
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_parameters)
            .with_ecc_unique_identifier(get_ecc_point())
            .build()
            .expect("Failed to build Public structure")
    }

    #[test]
    fn test_public_to_decoded_key_ecc() {
        let public_ecc = get_ext_ecc_pub();
        let decoded_key = DecodedKey::try_from(public_ecc)
            .expect("Failed to convert Public structure to DecodedKey (ECC).");

        match decoded_key {
            DecodedKey::RsaPublicKey(..) => panic!("ECC key was decoded to RsaPublicKey!"),
            DecodedKey::EcPoint(ec_point) => {
                assert_eq!(ec_point.to_vec(), EC_POINT.to_vec());
            }
        }
    }

    #[test]
    fn test_public_to_subject_public_key_info_ecc() {
        let public_ecc = get_ext_ecc_pub();
        let key = SubjectPublicKeyInfo::try_from(public_ecc)
            .expect("Failed to convert Public structure to SubjectPublicKeyInfo (ECC).");
        assert_eq!(
            key.algorithm,
            AlgorithmIdentifier::new_elliptic_curve(EcParameters::NamedCurve(
                picky_asn1_x509::oids::secp256r1().into()
            ))
        );
        match key.subject_public_key {
            PublicKey::Ec(ec_point) => {
                let ec_point_bitstring: BitString = ec_point.into();
                let ec_point_vec: Vec<u8> = ec_point_bitstring.into();
                assert_eq!(ec_point_vec, EC_POINT.to_vec());
            }
            _ => panic!("PublicKey of SubjectPublicKeyInfo is not an instance for ECC"),
        }
    }
}
