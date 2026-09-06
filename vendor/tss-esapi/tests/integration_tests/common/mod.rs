// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::{
    convert::{TryFrom, TryInto},
    env,
    str::FromStr,
    sync::Once,
};

use tss_esapi::{
    abstraction::{cipher::Cipher, pcr::PcrData},
    attributes::ObjectAttributes,
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    interface_types::{
        algorithm::SymmetricMode,
        algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
        key_bits::RsaKeyBits,
        key_bits::{AesKeyBits, Sm4KeyBits},
        resource_handles::Hierarchy,
        session_handles::PolicySession,
    },
    structures::{
        Digest, EccParameter, EccPoint, EccScheme, EccSignature, HashAgile, HashScheme, HmacScheme,
        KeyDerivationFunctionScheme, KeyedHashScheme, MaxBuffer, PcrSelectionListBuilder, PcrSlot,
        Public, PublicBuilder, PublicEccParameters, PublicKeyRsa, PublicKeyedHashParameters,
        PublicRsaParameters, RsaExponent, RsaScheme, RsaSignature, Sensitive, Signature,
        SymmetricCipherParameters, SymmetricDefinition, SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    utils, Context,
};

mod marshall;
mod tpma_types_equality_checks;
mod tpml_types_equality_checks;
mod tpms_types_equality_checks;
mod tpmt_types_equality_checks;
pub use marshall::*;
pub use tpma_types_equality_checks::*;
pub use tpml_types_equality_checks::*;
pub use tpms_types_equality_checks::*;
pub use tpmt_types_equality_checks::*;

#[allow(dead_code)]
pub const HASH: [u8; 64] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0x69,
    0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2, 0x94,
    0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0xA2, 0x94, 0x8E,
    0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78, 0x37, 0x78,
];

#[allow(dead_code)]
pub const KEY: [u8; 256] = [
    231, 97, 201, 180, 0, 1, 185, 150, 85, 90, 174, 188, 105, 133, 188, 3, 206, 5, 222, 71, 185, 1,
    209, 243, 36, 130, 250, 116, 17, 0, 24, 4, 25, 225, 250, 198, 245, 210, 140, 23, 139, 169, 15,
    193, 4, 145, 52, 138, 149, 155, 238, 36, 74, 152, 179, 108, 200, 248, 250, 100, 115, 214, 166,
    165, 1, 27, 51, 11, 11, 244, 218, 157, 3, 174, 171, 142, 45, 8, 9, 36, 202, 171, 165, 43, 208,
    186, 232, 15, 241, 95, 81, 174, 189, 30, 213, 47, 86, 115, 239, 49, 214, 235, 151, 9, 189, 174,
    144, 238, 200, 201, 241, 157, 43, 37, 6, 96, 94, 152, 159, 205, 54, 9, 181, 14, 35, 246, 49,
    150, 163, 118, 242, 59, 54, 42, 221, 215, 248, 23, 18, 223, 179, 229, 0, 204, 65, 69, 166, 180,
    11, 49, 131, 96, 163, 96, 158, 7, 109, 119, 208, 17, 237, 125, 187, 121, 94, 65, 2, 86, 105,
    68, 51, 197, 73, 108, 185, 231, 126, 199, 81, 1, 251, 211, 45, 47, 15, 113, 135, 197, 152, 239,
    180, 111, 18, 192, 136, 222, 11, 99, 41, 248, 205, 253, 209, 56, 214, 32, 225, 3, 49, 161, 58,
    57, 190, 69, 86, 95, 185, 184, 155, 76, 8, 122, 104, 81, 222, 234, 246, 40, 98, 182, 90, 160,
    111, 74, 102, 36, 148, 99, 69, 207, 214, 104, 87, 128, 238, 26, 121, 107, 166, 4, 64, 5, 210,
    164, 162, 189,
];

pub fn publics() -> [Public; 4] {
    [
        Public::Rsa {
            object_attributes: ObjectAttributes::new_fixed_signing_key(),
            name_hashing_algorithm: HashingAlgorithm::Sha256,
            auth_policy: Digest::try_from(vec![0x55; 16]).unwrap(),
            parameters: PublicRsaParameters::new(
                SymmetricDefinitionObject::Aes {
                    key_bits: AesKeyBits::Aes192,
                    mode: SymmetricMode::Cfb,
                },
                RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)),
                RsaKeyBits::Rsa2048,
                RsaExponent::default(),
            ),
            unique: PublicKeyRsa::default(),
        },
        Public::Ecc {
            object_attributes: ObjectAttributes::new_fixed_signing_key(),
            name_hashing_algorithm: HashingAlgorithm::Sha256,
            auth_policy: Digest::try_from(vec![0x55; 16]).unwrap(),
            parameters: PublicEccParameters::new(
                SymmetricDefinitionObject::Camellia {
                    key_bits: tss_esapi::interface_types::key_bits::CamelliaKeyBits::Camellia128,
                    mode: SymmetricMode::Cfb,
                },
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha384)),
                tss_esapi::interface_types::ecc::EccCurve::NistP192,
                KeyDerivationFunctionScheme::Null,
            ),
            unique: EccPoint::new(EccParameter::default(), EccParameter::default()),
        },
        Public::KeyedHash {
            object_attributes: ObjectAttributes::new_fixed_signing_key(),
            name_hashing_algorithm: HashingAlgorithm::Sha256,
            auth_policy: Digest::try_from(vec![0x55; 16]).unwrap(),
            parameters: PublicKeyedHashParameters::new(KeyedHashScheme::Hmac {
                hmac_scheme: HmacScheme::new(HashingAlgorithm::Sha256),
            }),
            unique: Digest::try_from(vec![0x01; 16]).unwrap(),
        },
        Public::SymCipher {
            object_attributes: ObjectAttributes::new_fixed_signing_key(),
            name_hashing_algorithm: HashingAlgorithm::Sha256,
            auth_policy: Digest::try_from(vec![0x55; 16]).unwrap(),
            parameters: SymmetricCipherParameters::new(SymmetricDefinitionObject::Sm4 {
                key_bits: Sm4KeyBits::Sm4_128,
                mode: SymmetricMode::Cfb,
            }),
            unique: Digest::try_from(vec![0x44; 16]).unwrap(),
        },
    ]
}

pub fn signatures() -> [Signature; 4] {
    [
        Signature::RsaSsa(
            RsaSignature::create(
                HashingAlgorithm::Sha256,
                PublicKeyRsa::try_from(vec![0xaa; 256]).expect("Failed to create signature data"),
            )
            .expect("Failed to create signature"),
        ),
        Signature::EcDsa(
            EccSignature::create(
                HashingAlgorithm::Sha3_256,
                EccParameter::try_from(vec![0x33; 64]).expect("Failed to create s value"),
                EccParameter::try_from(vec![0x00; 64]).expect("Failed to create s value"),
            )
            .expect("Failed to create signature"),
        ),
        Signature::Hmac(HashAgile::new(
            HashingAlgorithm::Sha384,
            Digest::try_from(vec![0xde; 48]).expect("Failed to create digest"),
        )),
        Signature::Null,
    ]
}

pub fn sensitives() -> [Sensitive; 4] {
    [
        Sensitive::Rsa {
            auth_value: Default::default(),
            seed_value: Default::default(),
            sensitive: KEY.to_vec().try_into().unwrap(),
        },
        Sensitive::Ecc {
            auth_value: vec![0x00; 8].try_into().unwrap(),
            seed_value: Default::default(),
            sensitive: vec![0x11; 32].try_into().unwrap(),
        },
        Sensitive::Bits {
            auth_value: Default::default(),
            seed_value: vec![0x00; 8].try_into().unwrap(),
            sensitive: vec![0x11; 8].try_into().unwrap(),
        },
        Sensitive::Symmetric {
            auth_value: vec![0xde; 8].try_into().unwrap(),
            seed_value: HASH.to_vec().try_into().unwrap(),
            sensitive: vec![0x11; 16].try_into().unwrap(),
        },
    ]
}

static LOG_INIT: Once = Once::new();
#[allow(dead_code)]
pub fn setup_logging() {
    LOG_INIT.call_once(|| {
        env_logger::init();
    });
}

#[allow(dead_code)]
pub fn create_tcti() -> TctiNameConf {
    setup_logging();

    match env::var("TEST_TCTI") {
        Err(_) => TctiNameConf::Mssim(Default::default()),
        Ok(tctistr) => TctiNameConf::from_str(&tctistr).expect("Error parsing TEST_TCTI"),
    }
}

#[allow(dead_code)]
pub fn create_ctx_without_session() -> Context {
    let tcti = create_tcti();
    Context::new(tcti).unwrap()
}

#[allow(dead_code)]
pub fn create_ctx_with_session() -> Context {
    let mut ctx = create_ctx_without_session();
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .unwrap();
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(
        session.unwrap(),
        session_attributes,
        session_attributes_mask,
    )
    .unwrap();
    ctx.set_sessions((session, None, None));

    ctx
}

#[allow(dead_code)]
pub fn decryption_key_pub() -> Public {
    utils::create_restricted_decryption_rsa_public(
        Cipher::aes_256_cfb()
            .try_into()
            .expect("Failed to create symmetric object"),
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .expect("Failed to create a restricted decryption rsa public structure")
}

#[allow(dead_code)]
pub fn encryption_decryption_key_pub() -> Public {
    utils::create_unrestricted_encryption_decryption_rsa_public(
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .expect("Failed to create an unrestricted encryption decryption rsa public structure")
}

#[allow(dead_code)]
pub fn signing_key_pub() -> Public {
    utils::create_unrestricted_signing_rsa_public(
        RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .expect("Failed to create RSA scheme"),
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .expect("Failed to create an unrestricted signing rsa public structure")
}

#[allow(dead_code)]
pub fn get_pcr_policy_digest(
    context: &mut Context,
    mangle: bool,
    do_trial: bool,
) -> (Digest, PolicySession) {
    let old_ses = context.sessions();
    context.clear_sessions();

    // Read the pcr values using pcr_read
    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot1])
        .build()
        .expect("Failed to create PcrSelectionList");

    let (_update_counter, pcr_selection_list_out, pcr_data) = context
        .pcr_read(pcr_selection_list.clone())
        .map(|(update_counter, read_pcr_selections, read_pcr_digests)| {
            (
                update_counter,
                read_pcr_selections.clone(),
                PcrData::create(&read_pcr_selections, &read_pcr_digests)
                    .expect("Failed to create PcrData"),
            )
        })
        .expect("Failed to call pcr_read");

    assert_eq!(pcr_selection_list, pcr_selection_list_out);
    // Run pcr_policy command.
    //
    // "If this command is used for a trial policySession,
    // policySession→policyDigest will be updated using the
    // values from the command rather than the values from a digest of the TPM PCR."
    //
    // "TPM2_Quote() and TPM2_PolicyPCR() digest the concatenation of PCR."
    let mut concatenated_pcr_values = [
        pcr_data
            .pcr_bank(HashingAlgorithm::Sha256)
            .unwrap()
            .get_digest(PcrSlot::Slot0)
            .unwrap()
            .value(),
        pcr_data
            .pcr_bank(HashingAlgorithm::Sha256)
            .unwrap()
            .get_digest(PcrSlot::Slot1)
            .unwrap()
            .value(),
    ]
    .concat();

    if mangle {
        concatenated_pcr_values[0] = 0x00;
    }

    let (hashed_data, _ticket) = context
        .hash(
            MaxBuffer::try_from(concatenated_pcr_values.to_vec()).unwrap(),
            HashingAlgorithm::Sha256,
            Hierarchy::Owner,
        )
        .unwrap();

    if do_trial {
        // Create a trial policy session to use in calls to the policy
        // context methods.
        let trial_policy_auth_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");

        let (trial_policy_auth_session_attributes, trial_policy_auth_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_policy_auth_session,
                trial_policy_auth_session_attributes,
                trial_policy_auth_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let trial_policy_session = PolicySession::try_from(trial_policy_auth_session)
            .expect("Failed to convert auth session into policy session");
        // There should be no errors setting pcr policy for trial session.
        context
            .policy_pcr(trial_policy_session, hashed_data, pcr_selection_list)
            .expect("Failed to call policy pcr");

        // There is now a policy digest that can be retrieved and used.
        let digest = context
            .policy_get_digest(trial_policy_session)
            .expect("Failed to call policy_get_digest");

        // Restore old sessions
        context.set_sessions(old_ses);

        (digest, trial_policy_session)
    } else {
        // Create a policy session to use in calls to the policy
        // context methods.
        let policy_auth_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");

        let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                policy_auth_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let policy_session = PolicySession::try_from(policy_auth_session)
            .expect("Failed to convert auth session into policy session");
        // There should be no errors setting pcr policy for trial session.
        context
            .policy_pcr(policy_session, hashed_data, pcr_selection_list)
            .expect("Failed to call policy_pcr");

        // There is now a policy digest that can be retrieved and used.
        let digest = context
            .policy_get_digest(policy_session)
            .expect("Failed to call policy_get_digest");

        // Restore old sessions
        context.set_sessions(old_ses);

        (digest, policy_session)
    }
}

#[allow(dead_code)]
pub fn create_public_sealed_object() -> Public {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_admin_with_policy(true)
        .with_user_with_auth(true)
        .build()
        .expect("Failed to create object attributes");

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_auth_policy(Default::default())
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .expect("Failed to create public structure.")
}
