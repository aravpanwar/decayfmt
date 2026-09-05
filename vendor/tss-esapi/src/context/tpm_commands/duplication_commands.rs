// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::Context;
use crate::{
    handles::ObjectHandle,
    structures::{Data, EncryptedSecret, Private, Public, SymmetricDefinitionObject},
    tss2_esys::{Esys_Duplicate, Esys_Import},
    Error, Result,
};
use log::error;

use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Duplicate a loaded object so that it may be used in a different hierarchy.
    ///
    /// # Details
    /// This command duplicates a loaded object so that it may be used in a different hierarchy.
    /// The new parent key for the duplicate may be on the same or different TPM or the Null hierarchy.
    /// Only the public area of `new_parent_handle` is required to be loaded.
    ///
    /// # Arguments
    /// * `object_to_duplicate` - An [ObjectHandle] of the object that will be duplicated.
    /// * `new_parent_handle` - An [ObjectHandle] of the new parent.
    /// * `encryption_key_in` - An optional encryption key. If this parameter is `None`
    ///   then a [default value][Default::default] is used.
    /// * `symmetric_alg` - Symmetric algorithm to be used for the inner wrapper.
    ///
    /// The `object_to_duplicate` need to be have Fixed TPM and Fixed Parent attributes set to `false`.
    ///
    /// # Returns
    /// The command returns a tuple consisting of:
    /// * `encryption_key_out` - TPM generated, symmetric encryption key for the inner wrapper if
    ///   `symmetric_alg` is not `Null`.
    /// * `duplicate` - Private area that may be encrypted.
    /// * `out_sym_seed` - Seed protected by the asymmetric algorithms of new parent.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::convert::{TryFrom, TryInto};
    /// # use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
    /// # use tss_esapi::constants::{CommandCode, SessionType};
    /// # use tss_esapi::handles::ObjectHandle;
    /// # use tss_esapi::interface_types::{
    /// #     algorithm::{HashingAlgorithm, PublicAlgorithm},
    /// #     key_bits::RsaKeyBits,
    /// #     resource_handles::Hierarchy,
    /// #     session_handles::PolicySession,
    /// # };
    /// # use tss_esapi::structures::SymmetricDefinition;
    /// # use tss_esapi::structures::{
    /// #     PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme,
    /// #     RsaExponent,
    /// # };
    /// use tss_esapi::structures::SymmetricDefinitionObject;
    /// # use tss_esapi::abstraction::cipher::Cipher;
    /// # use tss_esapi::{Context, TctiNameConf};
    /// #
    /// # let mut context = // ...
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # let trial_session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Trial,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Start auth session failed")
    /// #     .expect("Start auth session returned a NONE handle");
    /// #
    /// # let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
    /// #     SessionAttributesBuilder::new()
    /// #         .with_decrypt(true)
    /// #         .with_encrypt(true)
    /// #         .build();
    /// # context
    /// #     .tr_sess_set_attributes(
    /// #         trial_session,
    /// #         policy_auth_session_attributes,
    /// #         policy_auth_session_attributes_mask,
    /// #     )
    /// #     .expect("tr_sess_set_attributes call failed");
    /// #
    /// # let policy_session = PolicySession::try_from(trial_session)
    /// #     .expect("Failed to convert auth session into policy session");
    /// #
    /// # context
    /// #     .policy_auth_value(policy_session)
    /// #     .expect("Policy auth value");
    /// #
    /// # context
    /// #     .policy_command_code(policy_session, CommandCode::Duplicate)
    /// #     .expect("Policy command code");
    /// #
    /// # /// Digest of the policy that allows duplication
    /// # let digest = context
    /// #     .policy_get_digest(policy_session)
    /// #     .expect("Could retrieve digest");
    /// #
    /// # drop(context);
    /// # let mut context = // ...
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # let session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Hmac,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Start auth session failed")
    /// #     .expect("Start auth session returned a NONE handle");
    /// #
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// #
    /// # context.tr_sess_set_attributes(
    /// #     session,
    /// #     session_attributes,
    /// #     session_attributes_mask,
    /// # ).unwrap();
    /// #
    /// # context.set_sessions((Some(session), None, None));
    /// #
    /// # // Attributes of parent objects. The `restricted` attribute need
    /// # // to be `true` so that parents can act as storage keys.
    /// # let parent_object_attributes = ObjectAttributesBuilder::new()
    /// #     .with_fixed_tpm(true)
    /// #     .with_fixed_parent(true)
    /// #     .with_sensitive_data_origin(true)
    /// #     .with_user_with_auth(true)
    /// #     .with_decrypt(true)
    /// #     .with_sign_encrypt(false)
    /// #     .with_restricted(true)
    /// #     .build()
    /// #     .unwrap();
    /// #
    /// # let parent_public = PublicBuilder::new()
    /// #     .with_public_algorithm(PublicAlgorithm::Rsa)
    /// #     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_object_attributes(parent_object_attributes)
    /// #     .with_rsa_parameters(
    /// #         PublicRsaParametersBuilder::new_restricted_decryption_key(
    /// #             Cipher::aes_256_cfb().try_into().unwrap(),
    /// #             RsaKeyBits::Rsa2048,
    /// #             RsaExponent::default(),
    /// #         )
    /// #         .build()
    /// #         .unwrap(),
    /// #     )
    /// #     .with_rsa_unique_identifier(PublicKeyRsa::default())
    /// #     .build()
    /// #     .unwrap();
    /// #
    /// # let parent_of_object_to_duplicate_handle = context
    /// #     .create_primary(
    /// #         Hierarchy::Owner,
    /// #         parent_public.clone(),
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #     )
    /// #     .unwrap()
    /// #     .key_handle;
    /// #
    /// # // Fixed TPM and Fixed Parent should be "false" for an object
    /// # // to be eligible for duplication
    /// # let object_attributes = ObjectAttributesBuilder::new()
    /// #     .with_fixed_tpm(false)
    /// #     .with_fixed_parent(false)
    /// #     .with_sensitive_data_origin(true)
    /// #     .with_user_with_auth(true)
    /// #     .with_decrypt(true)
    /// #     .with_sign_encrypt(true)
    /// #     .with_restricted(false)
    /// #     .build()
    /// #     .expect("Attributes to be valid");
    /// #
    /// # let public_child = PublicBuilder::new()
    /// #     .with_public_algorithm(PublicAlgorithm::Rsa)
    /// #     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_object_attributes(object_attributes)
    /// #     .with_auth_policy(digest)
    /// #     .with_rsa_parameters(
    /// #         PublicRsaParametersBuilder::new()
    /// #             .with_scheme(RsaScheme::Null)
    /// #             .with_key_bits(RsaKeyBits::Rsa2048)
    /// #             .with_is_signing_key(true)
    /// #             .with_is_decryption_key(true)
    /// #             .with_restricted(false)
    /// #             .build()
    /// #             .expect("Params to be valid"),
    /// #     )
    /// #     .with_rsa_unique_identifier(PublicKeyRsa::default())
    /// #     .build()
    /// #     .expect("public to be valid");
    /// #
    /// # let result = context
    /// #     .create(
    /// #         parent_of_object_to_duplicate_handle,
    /// #         public_child,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #     )
    /// #     .unwrap();
    /// #
    /// # let object_to_duplicate_handle: ObjectHandle = context
    /// #     .load(
    /// #         parent_of_object_to_duplicate_handle,
    /// #         result.out_private.clone(),
    /// #         result.out_public,
    /// #     )
    /// #     .unwrap()
    /// #     .into();
    /// #
    /// # let new_parent_handle: ObjectHandle = context
    /// #     .create_primary(
    /// #         Hierarchy::Owner,
    /// #         parent_public,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #     )
    /// #     .unwrap()
    /// #     .key_handle
    /// #     .into();
    /// #
    /// # context.set_sessions((None, None, None));
    /// #
    /// # // Create a Policy session with the same exact attributes
    /// # // as the trial session so that the session digest stays
    /// # // the same.
    /// # let policy_auth_session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Policy,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Start auth session failed")
    /// #     .expect("Start auth session returned a NONE handle");
    /// #
    /// # let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
    /// #     SessionAttributesBuilder::new()
    /// #         .with_decrypt(true)
    /// #         .with_encrypt(true)
    /// #         .build();
    /// # context
    /// #     .tr_sess_set_attributes(
    /// #         policy_auth_session,
    /// #         policy_auth_session_attributes,
    /// #         policy_auth_session_attributes_mask,
    /// #     )
    /// #     .expect("tr_sess_set_attributes call failed");
    /// #
    /// # let policy_session = PolicySession::try_from(policy_auth_session)
    /// #     .expect("Failed to convert auth session into policy session");
    /// #
    /// # context
    /// #     .policy_auth_value(policy_session)
    /// #     .expect("Policy auth value");
    /// #
    /// # context
    /// #     .policy_command_code(policy_session, CommandCode::Duplicate)
    /// #     .unwrap();
    /// #
    /// # context.set_sessions((Some(policy_auth_session), None, None));
    ///
    /// let (encryption_key_out, duplicate, out_sym_seed) = context
    ///     .duplicate(
    ///         object_to_duplicate_handle,
    ///         new_parent_handle,
    ///         None,
    ///         SymmetricDefinitionObject::Null,
    ///     )
    ///     .unwrap();
    /// # eprintln!("D: {:?}, P: {:?}, S: {:?}", encryption_key_out, duplicate, out_sym_seed);
    /// ```
    pub fn duplicate(
        &mut self,
        object_to_duplicate: ObjectHandle,
        new_parent_handle: ObjectHandle,
        encryption_key_in: Option<Data>,
        symmetric_alg: SymmetricDefinitionObject,
    ) -> Result<(Data, Private, EncryptedSecret)> {
        let mut encryption_key_out_ptr = null_mut();
        let mut duplicate_ptr = null_mut();
        let mut out_sym_seed_ptr = null_mut();
        let ret = unsafe {
            Esys_Duplicate(
                self.mut_context(),
                object_to_duplicate.into(),
                new_parent_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                &encryption_key_in.unwrap_or_default().into(),
                &symmetric_alg.into(),
                &mut encryption_key_out_ptr,
                &mut duplicate_ptr,
                &mut out_sym_seed_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            Ok((
                Data::try_from(Context::ffi_data_to_owned(encryption_key_out_ptr))?,
                Private::try_from(Context::ffi_data_to_owned(duplicate_ptr))?,
                EncryptedSecret::try_from(Context::ffi_data_to_owned(out_sym_seed_ptr))?,
            ))
        } else {
            error!("Error when performing duplication: {}", ret);
            Err(ret)
        }
    }

    // Missing function: Rewrap

    /// Import attaches imported object to a new parent.
    ///
    /// # Details
    /// This command allows an object to be encrypted using the symmetric
    /// encryption values of a Storage Key. After encryption, the
    /// object may be loaded and used in the new hierarchy. The
    /// imported object (duplicate) may be singly encrypted, multiply
    /// encrypted, or unencrypted.
    ///
    /// # Arguments
    /// * `parent_handle` - An [ObjectHandle] of the new parent for the object.
    /// * `encryption_key` - An optional symmetric encryption key used as the inner wrapper.
    ///   If `encryption_key` is `None` then a [default value][Default::default] is used.
    /// * `public` - A [Public] of the imported object.
    /// * `duplicate` - A symmetrically encrypted duplicated object.
    /// * `encrypted_secret` - The seed for the symmetric key and HMAC key.
    /// * `symmetric_alg` - Symmetric algorithm to be used for the inner wrapper.
    ///
    /// The `public` is needed to check the integrity value for `duplicate`.
    ///
    /// # Returns
    /// The command returns the sensitive area encrypted with the symmetric key of `parent_handle`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::convert::{TryFrom, TryInto};
    /// # use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
    /// # use tss_esapi::constants::{CommandCode, SessionType};
    /// # use tss_esapi::handles::ObjectHandle;
    /// # use tss_esapi::interface_types::{
    /// #     algorithm::{HashingAlgorithm, PublicAlgorithm},
    /// #     key_bits::RsaKeyBits,
    /// #     resource_handles::Hierarchy,
    /// #     session_handles::PolicySession,
    /// # };
    /// # use tss_esapi::structures::SymmetricDefinition;
    /// # use tss_esapi::structures::{
    /// #     PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme,
    /// #     RsaExponent,
    /// # };
    /// use tss_esapi::structures::SymmetricDefinitionObject;
    /// # use tss_esapi::abstraction::cipher::Cipher;
    /// # use tss_esapi::{Context, TctiNameConf};
    /// #
    /// # let mut context = // ...
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # let trial_session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Trial,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Start auth session failed")
    /// #     .expect("Start auth session returned a NONE handle");
    /// #
    /// # let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
    /// #     SessionAttributesBuilder::new()
    /// #         .with_decrypt(true)
    /// #         .with_encrypt(true)
    /// #         .build();
    /// # context
    /// #     .tr_sess_set_attributes(
    /// #         trial_session,
    /// #         policy_auth_session_attributes,
    /// #         policy_auth_session_attributes_mask,
    /// #     )
    /// #     .expect("tr_sess_set_attributes call failed");
    /// #
    /// # let policy_session = PolicySession::try_from(trial_session)
    /// #     .expect("Failed to convert auth session into policy session");
    /// #
    /// # context
    /// #     .policy_auth_value(policy_session)
    /// #     .expect("Policy auth value");
    /// #
    /// # context
    /// #     .policy_command_code(policy_session, CommandCode::Duplicate)
    /// #     .expect("Policy command code");
    /// #
    /// # /// Digest of the policy that allows duplication
    /// # let digest = context
    /// #     .policy_get_digest(policy_session)
    /// #     .expect("Could retrieve digest");
    /// #
    /// # drop(context);
    /// # let mut context = // ...
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # let session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Hmac,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Start auth session failed")
    /// #     .expect("Start auth session returned a NONE handle");
    /// #
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// #
    /// # context.tr_sess_set_attributes(
    /// #     session,
    /// #     session_attributes,
    /// #     session_attributes_mask,
    /// # ).unwrap();
    /// #
    /// # context.set_sessions((Some(session), None, None));
    /// #
    /// # // Attributes of parent objects. The `restricted` attribute need
    /// # // to be `true` so that parents can act as storage keys.
    /// # let parent_object_attributes = ObjectAttributesBuilder::new()
    /// #     .with_fixed_tpm(true)
    /// #     .with_fixed_parent(true)
    /// #     .with_sensitive_data_origin(true)
    /// #     .with_user_with_auth(true)
    /// #     .with_decrypt(true)
    /// #     .with_sign_encrypt(false)
    /// #     .with_restricted(true)
    /// #     .build()
    /// #     .unwrap();
    /// #
    /// # let parent_public = PublicBuilder::new()
    /// #     .with_public_algorithm(PublicAlgorithm::Rsa)
    /// #     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_object_attributes(parent_object_attributes)
    /// #     .with_rsa_parameters(
    /// #         PublicRsaParametersBuilder::new_restricted_decryption_key(
    /// #             Cipher::aes_256_cfb().try_into().unwrap(),
    /// #             RsaKeyBits::Rsa2048,
    /// #             RsaExponent::default(),
    /// #         )
    /// #         .build()
    /// #         .unwrap(),
    /// #     )
    /// #     .with_rsa_unique_identifier(PublicKeyRsa::default())
    /// #     .build()
    /// #     .unwrap();
    /// #
    /// # let parent_of_object_to_duplicate_handle = context
    /// #     .create_primary(
    /// #         Hierarchy::Owner,
    /// #         parent_public.clone(),
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #     )
    /// #     .unwrap()
    /// #     .key_handle;
    /// #
    /// # // Fixed TPM and Fixed Parent should be "false" for an object
    /// # // to be eligible for duplication
    /// # let object_attributes = ObjectAttributesBuilder::new()
    /// #     .with_fixed_tpm(false)
    /// #     .with_fixed_parent(false)
    /// #     .with_sensitive_data_origin(true)
    /// #     .with_user_with_auth(true)
    /// #     .with_decrypt(true)
    /// #     .with_sign_encrypt(true)
    /// #     .with_restricted(false)
    /// #     .build()
    /// #     .expect("Attributes to be valid");
    /// #
    /// # let public_child = PublicBuilder::new()
    /// #     .with_public_algorithm(PublicAlgorithm::Rsa)
    /// #     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_object_attributes(object_attributes)
    /// #     .with_auth_policy(digest)
    /// #     .with_rsa_parameters(
    /// #         PublicRsaParametersBuilder::new()
    /// #             .with_scheme(RsaScheme::Null)
    /// #             .with_key_bits(RsaKeyBits::Rsa2048)
    /// #             .with_is_signing_key(true)
    /// #             .with_is_decryption_key(true)
    /// #             .with_restricted(false)
    /// #             .build()
    /// #             .expect("Params to be valid"),
    /// #     )
    /// #     .with_rsa_unique_identifier(PublicKeyRsa::default())
    /// #     .build()
    /// #     .expect("public to be valid");
    /// #
    /// # let result = context
    /// #     .create(
    /// #         parent_of_object_to_duplicate_handle,
    /// #         public_child,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #     )
    /// #     .unwrap();
    /// #
    /// # let object_to_duplicate_handle: ObjectHandle = context
    /// #     .load(
    /// #         parent_of_object_to_duplicate_handle,
    /// #         result.out_private.clone(),
    /// #         result.out_public,
    /// #     )
    /// #     .unwrap()
    /// #     .into();
    /// #
    /// # let new_parent_handle: ObjectHandle = context
    /// #     .create_primary(
    /// #         Hierarchy::Owner,
    /// #         parent_public,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #     )
    /// #     .unwrap()
    /// #     .key_handle
    /// #     .into();
    /// #
    /// # context.set_sessions((None, None, None));
    /// #
    /// # // Create a Policy session with the same exact attributes
    /// # // as the trial session so that the session digest stays
    /// # // the same.
    /// # let policy_auth_session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Policy,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Start auth session failed")
    /// #     .expect("Start auth session returned a NONE handle");
    /// #
    /// # let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
    /// #     SessionAttributesBuilder::new()
    /// #         .with_decrypt(true)
    /// #         .with_encrypt(true)
    /// #         .build();
    /// # context
    /// #     .tr_sess_set_attributes(
    /// #         policy_auth_session,
    /// #         policy_auth_session_attributes,
    /// #         policy_auth_session_attributes_mask,
    /// #     )
    /// #     .expect("tr_sess_set_attributes call failed");
    /// #
    /// # let policy_session = PolicySession::try_from(policy_auth_session)
    /// #     .expect("Failed to convert auth session into policy session");
    /// #
    /// # context
    /// #     .policy_auth_value(policy_session)
    /// #     .expect("Policy auth value");
    /// #
    /// # context
    /// #     .policy_command_code(policy_session, CommandCode::Duplicate)
    /// #     .unwrap();
    /// #
    /// # context.set_sessions((Some(policy_auth_session), None, None));
    /// #
    /// # let (encryption_key_out, duplicate, out_sym_seed) = context
    /// #     .duplicate(
    /// #         object_to_duplicate_handle,
    /// #         new_parent_handle,
    /// #         None,
    /// #         SymmetricDefinitionObject::Null,
    /// #     )
    /// #     .unwrap();
    /// # eprintln!("D: {:?}, P: {:?}, S: {:?}", encryption_key_out, duplicate, out_sym_seed);
    /// # let public = context.read_public(object_to_duplicate_handle.into()).unwrap().0;
    /// #
    /// # let session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Hmac,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .unwrap();
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(
    /// #     session.unwrap(),
    /// #     session_attributes,
    /// #     session_attributes_mask,
    /// # )
    /// # .unwrap();
    /// # context.set_sessions((session, None, None));
    ///
    /// // `encryption_key_out`, `duplicate` and `out_sym_seed` are generated
    /// // by `duplicate` function
    /// let private = context.import(
    ///     new_parent_handle,
    ///     Some(encryption_key_out),
    ///     public,
    ///     duplicate,
    ///     out_sym_seed,
    ///     SymmetricDefinitionObject::Null,
    ///  ).unwrap();
    /// #
    /// # eprintln!("P: {:?}", private);
    /// ```
    pub fn import(
        &mut self,
        parent_handle: ObjectHandle,
        encryption_key: Option<Data>,
        public: Public,
        duplicate: Private,
        encrypted_secret: EncryptedSecret,
        symmetric_alg: SymmetricDefinitionObject,
    ) -> Result<Private> {
        let mut out_private_ptr = null_mut();
        let ret = unsafe {
            Esys_Import(
                self.mut_context(),
                parent_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                &encryption_key.unwrap_or_default().into(),
                &public.try_into()?,
                &duplicate.into(),
                &encrypted_secret.into(),
                &symmetric_alg.into(),
                &mut out_private_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            Private::try_from(Context::ffi_data_to_owned(out_private_ptr))
        } else {
            error!("Error when performing import: {}", ret);
            Err(ret)
        }
    }
}
