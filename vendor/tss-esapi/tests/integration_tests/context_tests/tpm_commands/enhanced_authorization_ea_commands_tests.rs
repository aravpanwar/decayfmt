// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_policy_signed {
    use crate::common::{create_ctx_with_session, signing_key_pub};
    use std::{convert::TryFrom, time::Duration};
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{
            algorithm::HashingAlgorithm, resource_handles::Hierarchy,
            session_handles::PolicySession,
        },
        structures::{Digest, Nonce, PublicKeyRsa, RsaSignature, Signature, SymmetricDefinition},
    };
    #[test]
    fn test_policy_signed() {
        let mut context = create_ctx_with_session();

        let key_handle = context
            .create_primary(Hierarchy::Owner, signing_key_pub(), None, None, None, None)
            .unwrap()
            .key_handle;

        let trial_policy_auth_session = context
            .execute_without_session(|ctx| {
                ctx.start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Trial,
                    SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )
            })
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

        let nonce_tpm = Nonce::try_from(vec![1, 2, 3]).expect("Failed to convert data into Nonce");
        let cp_hash_a =
            Digest::try_from(vec![1, 2, 3]).expect("Failed to convert data into Digest");
        let policy_ref = Nonce::try_from(vec![1, 2, 3]).expect("Failed to convert data into Nonce");

        let signature = Signature::RsaSsa(
            RsaSignature::create(
                HashingAlgorithm::Sha256,
                PublicKeyRsa::try_from(vec![0xab; 32])
                    .expect("Failed to create Public RSA key structure for RSA signature"),
            )
            .expect("Failed to create RSA signature"),
        );

        let trial_policy_session = PolicySession::try_from(trial_policy_auth_session)
            .expect("Failed to convert auth session into policy session");

        context
            .policy_signed(
                trial_policy_session,
                key_handle.into(),
                nonce_tpm,
                cp_hash_a,
                policy_ref,
                Some(Duration::from_secs(3600)),
                signature,
            )
            .expect("Call to policy_signed failed");
    }
}

mod test_policy_secret {
    use crate::common::create_ctx_with_session;
    use std::{convert::TryFrom, time::Duration};
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        handles::AuthHandle,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::{Digest, Nonce, SymmetricDefinition},
    };
    #[test]
    fn test_policy_secret() {
        let mut context = create_ctx_with_session();

        let trial_policy_auth_session = context
            .execute_without_session(|ctx| {
                ctx.start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Trial,
                    SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )
            })
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

        let nonce_tpm = Nonce::try_from(vec![1, 2, 3]).unwrap();
        let cp_hash_a = Digest::try_from(vec![1, 2, 3]).unwrap();
        let policy_ref = Nonce::try_from(vec![1, 2, 3]).unwrap();

        let trial_policy_session = PolicySession::try_from(trial_policy_auth_session)
            .expect("Failed to convert auth session into policy session");

        context
            .policy_secret(
                trial_policy_session,
                AuthHandle::Endorsement,
                nonce_tpm,
                cp_hash_a,
                policy_ref,
                Some(Duration::from_secs(3600)),
            )
            .expect("Failed to call policy_secret");
    }
}

mod test_policy_or {
    use crate::common::{create_ctx_without_session, get_pcr_policy_digest};
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::{DigestList, SymmetricDefinition},
    };
    #[test]
    fn test_policy_or() {
        let mut context = create_ctx_without_session();
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

        let mut digest_list = DigestList::new();
        digest_list
            .add(get_pcr_policy_digest(&mut context, true, true).0)
            .unwrap();
        digest_list
            .add(get_pcr_policy_digest(&mut context, false, true).0)
            .unwrap();
        let trial_policy_session = PolicySession::try_from(trial_policy_auth_session)
            .expect("Failed to convert auth session into policy session");
        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_or(trial_policy_session, digest_list)
            .unwrap();
    }
}

mod test_policy_pcr {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        abstraction::pcr::PcrData,
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{
            algorithm::HashingAlgorithm, resource_handles::Hierarchy,
            session_handles::PolicySession,
        },
        structures::{MaxBuffer, PcrSelectionListBuilder, PcrSlot, SymmetricDefinition},
    };

    #[test]
    fn test_policy_pcr_sha_256() {
        let mut context = create_ctx_without_session();
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
        let concatenated_pcr_values = MaxBuffer::try_from(
            [
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
            .concat()
            .to_vec(),
        )
        .unwrap();

        let (hashed_data, _ticket) = context
            .hash(
                concatenated_pcr_values,
                HashingAlgorithm::Sha256,
                Hierarchy::Owner,
            )
            .expect("Failed to call hash");
        let trial_policy_session = PolicySession::try_from(trial_policy_auth_session)
            .expect("Failed to convert auth session into policy session");
        // There should be no errors setting pcr policy for trial session.
        context
            .policy_pcr(trial_policy_session, hashed_data, pcr_selection_list)
            .expect("Failed to call policy_pcr");
    }
}

mod test_policy_locality {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::{LocalityAttributes, SessionAttributesBuilder},
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::SymmetricDefinition,
    };
    #[test]
    fn test_policy_locality() {
        let mut context = create_ctx_without_session();
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
        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_locality(trial_policy_session, LocalityAttributes::LOCALITY_THREE)
            .unwrap();
    }
}

mod test_policy_command_code {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{CommandCode, SessionType},
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::SymmetricDefinition,
    };
    #[test]
    fn test_policy_command_code() {
        let mut context = create_ctx_without_session();
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
        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_command_code(trial_policy_session, CommandCode::Unseal)
            .unwrap();
    }
}

mod test_policy_physical_presence {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::SymmetricDefinition,
    };
    #[test]
    fn test_policy_physical_presence() {
        let mut context = create_ctx_without_session();
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
        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_physical_presence(trial_policy_session)
            .unwrap();
    }
}

mod test_policy_cp_hash {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::{Digest, SymmetricDefinition},
    };
    #[test]
    fn test_policy_cp_hash() {
        let mut context = create_ctx_without_session();
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

        let test_dig = Digest::try_from(vec![
            252, 200, 17, 232, 137, 217, 130, 51, 54, 22, 184, 131, 2, 134, 99, 130, 175, 216, 159,
            174, 203, 165, 35, 19, 187, 56, 167, 208, 3, 128, 11, 12,
        ])
        .expect("Failed to create digest from data");
        let trial_policy_session = PolicySession::try_from(trial_policy_auth_session)
            .expect("Failed to convert auth session into policy session");
        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_cp_hash(trial_policy_session, test_dig)
            .unwrap();
    }
}

mod test_policy_name_hash {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::{Digest, SymmetricDefinition},
    };
    #[test]
    fn test_policy_name_hash() {
        let mut context = create_ctx_without_session();
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

        let test_dig = Digest::try_from(vec![
            252, 200, 17, 232, 137, 217, 130, 51, 54, 22, 184, 131, 2, 134, 99, 130, 175, 216, 159,
            174, 203, 165, 35, 19, 187, 56, 167, 208, 3, 128, 11, 12,
        ])
        .expect("Failed to create digest from data");
        let trial_policy_session = PolicySession::try_from(trial_policy_auth_session)
            .expect("Failed to convert auth session into policy session");
        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_name_hash(trial_policy_session, test_dig)
            .expect("Call to policy_name_hash failed");
    }
}

mod test_policy_authorize {
    use crate::common::{create_ctx_with_session, get_pcr_policy_digest, signing_key_pub};
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{Auth, MaxBuffer, Nonce, SignatureScheme},
        tss2_esys::{TPM2B_NONCE, TPMT_TK_HASHCHECK},
    };
    #[test]
    fn test_policy_authorize() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();
        let key_auth = Auth::try_from(random_digest).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;
        let key_name = context.tr_get_name(key_handle.into()).unwrap();

        let policy_ref: TPM2B_NONCE = Default::default();
        let (policy_digest, policy_ses) = get_pcr_policy_digest(&mut context, false, false);

        // aHash ≔ H_{aHashAlg}(approvedPolicy || policyRef)
        let ahash = context
            .hash(
                MaxBuffer::try_from(policy_digest.value().to_vec()).unwrap(),
                HashingAlgorithm::Sha256,
                Hierarchy::Null,
            )
            .unwrap()
            .0;

        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        // A signature over just the policy_digest, since the policy_ref is empty
        let signature = context
            .sign(
                key_handle,
                ahash.clone(),
                SignatureScheme::Null,
                validation.try_into().unwrap(),
            )
            .unwrap();
        let tkt = context
            .verify_signature(key_handle, ahash, signature)
            .unwrap();

        // Since the signature is over this sessions' state, it should be valid
        context
            .policy_authorize(
                policy_ses,
                policy_digest,
                Nonce::try_from(policy_ref).unwrap(),
                &key_name,
                tkt,
            )
            .unwrap();
    }
}

mod test_policy_auth_value {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::SymmetricDefinition,
    };
    #[test]
    fn test_policy_auth_value() {
        let mut context = create_ctx_without_session();
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
        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_auth_value(trial_policy_session)
            .expect("Failed to call policy auth value");
    }
}

mod test_policy_password {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::SymmetricDefinition,
    };
    #[test]
    fn test_policy_password() {
        let mut context = create_ctx_without_session();
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
        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_password(trial_policy_session)
            .expect("Failed to call policy_password");
    }
}

mod test_policy_get_digest {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        abstraction::pcr::PcrData,
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{
            algorithm::HashingAlgorithm, resource_handles::Hierarchy,
            session_handles::PolicySession,
        },
        structures::{MaxBuffer, PcrSelectionListBuilder, PcrSlot, SymmetricDefinition},
    };
    #[test]
    fn get_policy_digest() {
        let mut context = create_ctx_without_session();
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

        // Read the pcr values using pcr_read
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot1])
            .build()
            .expect("Failed to create PcrSelectionList");

        let trial_policy_session = PolicySession::try_from(trial_policy_auth_session)
            .expect("Failed to convert auth session into policy session");
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
        let concatenated_pcr_values = MaxBuffer::try_from(
            [
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
            .concat()
            .to_vec(),
        )
        .unwrap();

        let (hashed_data, _ticket) = context
            .hash(
                concatenated_pcr_values,
                HashingAlgorithm::Sha256,
                Hierarchy::Owner,
            )
            .unwrap();
        // There should be no errors setting pcr policy for trial session.
        context
            .policy_pcr(trial_policy_session, hashed_data, pcr_selection_list)
            .unwrap();

        // There is now a policy digest that can be retrieved and used.
        let retrieved_policy_digest = context.policy_get_digest(trial_policy_session).unwrap();

        // The algorithm is SHA256 so the expected size of the digest should be 32.
        assert_eq!(retrieved_policy_digest.value().len(), 32);
    }
}

mod test_policy_nv_written {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::SymmetricDefinition,
    };
    #[test]
    fn test_policy_nv_written() {
        let mut context = create_ctx_without_session();
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
        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_nv_written(trial_policy_session, true)
            .unwrap();
    }
}

mod test_policy_template {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::{Digest, Nonce, SymmetricDefinition},
    };
    #[test]
    fn basic_policy_template_test() {
        let trial_session_nonce = Nonce::try_from(vec![
            11, 12, 13, 14, 15, 16, 17, 18, 19, 11, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        ])
        .expect("Failed to create Nonce for trial session");

        let mut context = create_ctx_without_session();

        let trial_policy_auth_session = context
            .start_auth_session(
                None,
                None,
                Some(trial_session_nonce),
                SessionType::Trial,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha1,
            )
            .expect("Call to start_auth_session failed")
            .expect("Failed to get proper session");

        let template_hash = Digest::try_from(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ])
        .expect("Failed to create template hash digest");

        let trial_policy_session = PolicySession::try_from(trial_policy_auth_session)
            .expect("Failed to convert auth session into policy session");
        // TODO. DO not just panic but instead check error code
        // to see if the command is supported by the TPM and if
        // not log a warning but let the test pass.
        context
            .policy_template(trial_policy_session, template_hash)
            .expect("Failed to call policy_template");

        let expected_policy_template = Digest::try_from(vec![
            0xf6, 0x6d, 0x2a, 0x9c, 0x6e, 0xa8, 0xdf, 0x1a, 0x49, 0x3c, 0x42, 0xcc, 0xac, 0x6e,
            0x3d, 0x08, 0xc0, 0x84, 0xcf, 0x73,
        ])
        .expect("Failed to create the expected policy template digest");

        let policy_digest = context
            .policy_get_digest(trial_policy_session)
            .expect("Failed to get policy digest for trial session");

        assert_eq!(expected_policy_template, policy_digest);
    }
}
