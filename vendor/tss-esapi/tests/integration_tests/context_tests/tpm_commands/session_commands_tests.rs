// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_start_auth_session {
    use crate::common::{create_ctx_with_session, create_ctx_without_session, decryption_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{Nonce, SymmetricDefinition},
    };

    #[test]
    fn test_simple_sess() {
        let mut context = create_ctx_without_session();
        context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .unwrap();
    }

    #[test]
    fn test_nonce_sess() {
        let mut context = create_ctx_without_session();
        context
            .start_auth_session(
                None,
                None,
                Some(
                    Nonce::try_from(
                        [
                            128, 85, 22, 124, 85, 9, 12, 55, 23, 73, 1, 244, 102, 44, 95, 39, 10,
                        ]
                        .to_vec(),
                    )
                    .unwrap(),
                ),
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .unwrap();
    }

    #[test]
    fn test_bound_sess() {
        let mut context = create_ctx_with_session();
        let prim_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        context
            .start_auth_session(
                Some(prim_key_handle),
                Some(prim_key_handle.into()),
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .unwrap();
    }

    #[test]
    fn test_encrypted_start_sess() {
        let mut context = create_ctx_without_session();
        let encrypted_sess = context
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
            .with_encrypt(true)
            .with_audit(true)
            .build();
        context
            .tr_sess_set_attributes(
                encrypted_sess.unwrap(),
                session_attributes,
                session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let _ = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .unwrap();
    }

    #[test]
    fn test_authenticated_start_sess() {
        let mut context = create_ctx_without_session();
        let auth_sess = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .unwrap();

        context.execute_with_session(auth_sess, |ctx| {
            ctx.start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .unwrap_err();
        });
    }
}

mod test_policy_restart {
    use crate::common::{create_ctx_without_session, get_pcr_policy_digest};
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, session_handles::PolicySession},
        structures::{Digest, DigestList, SymmetricDefinition},
    };
    #[test]
    fn test_policy_restart() {
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
        let dig = context.policy_get_digest(trial_policy_session).unwrap();
        assert_eq!(
            dig,
            Digest::try_from(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ])
            .unwrap()
        );

        let mut digest_list = DigestList::new();
        digest_list
            .add(get_pcr_policy_digest(&mut context, true, true).0)
            .unwrap();
        digest_list
            .add(get_pcr_policy_digest(&mut context, false, true).0)
            .unwrap();
        context
            .policy_or(trial_policy_session, digest_list)
            .unwrap();

        context.policy_restart(trial_policy_session).unwrap();

        let dig = context.policy_get_digest(trial_policy_session).unwrap();
        assert_eq!(
            dig,
            Digest::try_from(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ])
            .unwrap()
        );
    }
}
