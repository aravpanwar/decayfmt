// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_duplicate {
    use crate::common::{create_ctx_with_session, create_ctx_without_session};
    use std::convert::TryFrom;
    use std::convert::TryInto;
    use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
    use tss_esapi::constants::SessionType;
    use tss_esapi::handles::ObjectHandle;
    use tss_esapi::interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
        session_handles::PolicySession,
    };
    use tss_esapi::structures::SymmetricDefinition;
    use tss_esapi::structures::{
        EccPoint, EccScheme, KeyDerivationFunctionScheme, PublicBuilder,
        PublicEccParametersBuilder, SymmetricDefinitionObject,
    };

    #[test]
    fn test_duplicate_and_import() {
        let mut context = create_ctx_with_session();

        // First: create a target parent object.
        // The key that we will duplicate will be a child of this target parent.
        let parent_object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(false)
            .with_restricted(true)
            .build()
            .expect("Attributes to be valid");

        let public_parent = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(parent_object_attributes)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::Null)
                    .with_curve(EccCurve::NistP256)
                    .with_is_signing_key(false)
                    .with_is_decryption_key(true)
                    .with_restricted(true)
                    .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()
                    .expect("Params to be valid"),
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .expect("public to be valid");

        let new_parent_handle = context
            .create_primary(
                Hierarchy::Owner,
                public_parent.clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        // The name of the parent will be used to restrict duplication to
        // only this one parent.
        let parent_name = context.read_public(new_parent_handle).unwrap().1;

        drop(context);

        // Trial session will be used to compute a policy digest.
        // The policy will allow key duplication to one specified target parent.
        // The target parent would be selected using "parent_name".
        let mut context = create_ctx_without_session();

        let trial_session = context
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

        let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let policy_session = PolicySession::try_from(trial_session)
            .expect("Failed to convert auth session into policy session");

        context
            .policy_duplication_select(
                policy_session,
                Vec::<u8>::new().try_into().unwrap(),
                parent_name.clone(),
                false,
            )
            .expect("Policy duplication select");

        // Policy digest will be used when constructing the child key.
        // It will allow the newly constructed key to be duplicated but
        // only to one specified parent.
        let digest = context
            .policy_get_digest(policy_session)
            .expect("Could retrieve digest");

        drop(context);
        let mut context = create_ctx_with_session();

        // Fixed TPM and Fixed Parent should be "false" for an object
        // to be eligible for duplication
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(false)
            .with_fixed_parent(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Attributes to be valid");

        let public_child = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            // Use policy digest computed using the trial session
            .with_auth_policy(digest)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::Null)
                    .with_curve(EccCurve::NistP256)
                    .with_is_signing_key(false)
                    .with_is_decryption_key(true)
                    .with_restricted(false)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()
                    .expect("Params to be valid"),
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .expect("public to be valid");

        // Re-create the new parent again.
        // Since the key specification did not change it will be the same parent
        // that was used to get the "parent_name".
        // In real world the new parent will likely be persisted in the TPM.
        let new_parent_handle: ObjectHandle = context
            .create_primary(
                Hierarchy::Owner,
                public_parent.clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle
            .into();

        let parent_of_object_to_duplicate_handle = context
            .create_primary(Hierarchy::Owner, public_parent, None, None, None, None)
            .unwrap()
            .key_handle;

        let result = context
            .create(
                parent_of_object_to_duplicate_handle,
                public_child,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let object_to_duplicate_handle: ObjectHandle = context
            .load(
                parent_of_object_to_duplicate_handle,
                result.out_private.clone(),
                result.out_public,
            )
            .unwrap()
            .into();

        // Object name of the duplicated object is needed to satisfy
        // real policy session.
        let object_name = context
            .read_public(object_to_duplicate_handle.into())
            .unwrap()
            .1;

        context.set_sessions((None, None, None));

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

        // Even if object name is not included in the policy digest ("false" as 3rd parameter)
        // Correct name needs to be set or the policy will fail.
        context
            .policy_duplication_select(policy_session, object_name, parent_name, false)
            .unwrap();
        context.set_sessions((Some(policy_auth_session), None, None));

        // Duplicate the object to new parent.
        let (data, duplicate, secret) = context
            .duplicate(
                object_to_duplicate_handle,
                new_parent_handle,
                None,
                SymmetricDefinitionObject::Null,
            )
            .unwrap();
        eprintln!("D: {:?}, P: {:?}, S: {:?}", data, duplicate, secret);

        // Public is also needed when transferring the duplicatee
        // for integrity validation.
        let public = context
            .read_public(object_to_duplicate_handle.into())
            .unwrap()
            .0;

        let session = context
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
        context
            .tr_sess_set_attributes(
                session.unwrap(),
                session_attributes,
                session_attributes_mask,
            )
            .unwrap();
        context.set_sessions((session, None, None));

        // Try to import the duplicated object.
        // Most parameters (with the exception of public) are passed from
        // the values returned from the call to `duplicate`.
        let private = context
            .import(
                new_parent_handle,
                Some(data),
                public,
                duplicate,
                secret,
                SymmetricDefinitionObject::Null,
            )
            .unwrap();

        eprintln!("P: {:?}", private);
    }
}
