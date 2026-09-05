// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_random {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::algorithm::HashingAlgorithm,
        structures::{SensitiveData, SymmetricDefinition},
    };

    #[test]
    fn test_encrypted_get_rand() {
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
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .with_audit(true)
            .build();
        context
            .tr_sess_set_attributes(encrypted_sess, session_attributes, session_attributes_mask)
            .expect("tr_sess_set_attributes call failed");

        context.set_sessions((Some(encrypted_sess), None, None));
        let _ = context.get_random(10).expect("call to get_rand failed");
    }

    #[test]
    fn test_authenticated_get_rand() {
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
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");

        context.set_sessions((Some(auth_sess), None, None));
        let _ = context.get_random(10).unwrap_err();
    }

    #[test]
    fn test_get_0_rand() {
        let mut context = create_ctx_without_session();
        let _ = context.get_random(0);
    }

    #[test]
    fn test_stir_random() {
        let mut context = create_ctx_without_session();
        let additional_data = SensitiveData::try_from(vec![1, 2, 3]).unwrap();
        context.stir_random(additional_data).unwrap();
    }
}
