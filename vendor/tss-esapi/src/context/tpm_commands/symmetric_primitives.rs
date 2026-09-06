// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::{KeyHandle, ObjectHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricMode},
        resource_handles::Hierarchy,
    },
    structures::{Digest, HashcheckTicket, InitialValue, MaxBuffer},
    tss2_esys::{Esys_EncryptDecrypt2, Esys_HMAC, Esys_Hash},
    Context, Error, Result,
};
use log::error;
use std::convert::TryFrom;
use std::ptr::null_mut;

impl Context {
    // Missing function: EncryptDecrypt, deprecated use EncryptDecrypt2 instead.

    /// Performs symmetric encryption or decryption of the data using
    /// the key associated with the `key_handle`
    ///
    /// # Arguments
    /// * `key_handle` -  A [KeyHandle] to the key to be used.
    /// * `decrypt` - A boolean indicating if the data should be decrypted or encrypted.
    ///   If set to true the data will be decrypted else encrypted.
    /// * `mode` - The [SymmetricMode] to be used.
    /// * `in_data` - The data that is going to be decrypted or encrypted.
    /// * `initial_value_in` - An initial value as required by the algorithm.
    ///
    /// # Example
    /// ```rust
    /// # use tss_esapi::{
    /// #     constants::AlgorithmIdentifier,
    /// #     attributes::ObjectAttributesBuilder,
    /// #     Context, tcti_ldr::TctiNameConf, Result,
    /// #     structures::{
    /// #         Auth, InitialValue, MaxBuffer, SensitiveData, RsaExponent, SymmetricDefinitionObject,
    /// #         SymmetricCipherParameters, PublicBuilder,
    /// #     },
    /// #     interface_types::{
    /// #         algorithm::{PublicAlgorithm, HashingAlgorithm},
    /// #         key_bits::RsaKeyBits,
    /// #     },
    /// # };
    /// use tss_esapi::interface_types::session_handles::AuthSession;
    /// use tss_esapi::interface_types::algorithm::SymmetricMode;
    /// # use std::convert::TryFrom;
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # // Set auth for owner
    /// # context
    /// #     .tr_set_auth(tss_esapi::interface_types::resource_handles::Hierarchy::Owner.into(), Auth::default())
    /// #     .expect("Failed to set auth to empty for owner");
    /// # // Create primary key auth
    /// # let mut random_digest = vec![0u8; 16];
    /// # getrandom::fill(&mut random_digest).expect("get_rand call failed");
    /// # let primary_key_auth = Auth::try_from(
    /// #     random_digest
    /// # )
    /// # .expect("Failed to create primary key auth");
    /// # // Create primary key
    /// # let primary_key_handle = context.execute_with_session(Some(AuthSession::Password), |ctx| {
    /// #     ctx.create_primary(
    /// #         tss_esapi::interface_types::resource_handles::Hierarchy::Owner,
    /// #         tss_esapi::utils::create_restricted_decryption_rsa_public(
    /// #             SymmetricDefinitionObject::AES_256_CFB,
    /// #             RsaKeyBits::Rsa2048,
    /// #             RsaExponent::default(),
    /// #         )
    /// #         .expect("Failed to create public for primary key"),
    /// #         Some(primary_key_auth.clone()),
    /// #         None,
    /// #         None,
    /// #         None,
    /// #     )
    /// #     .expect("Failed to create primary handle")
    /// #     .key_handle
    /// # });
    /// # // Set auth for the primary key handle
    /// # context
    /// #     .tr_set_auth(primary_key_handle.into(), primary_key_auth)
    /// #     .expect("Failed to set auth from primary key handle.");
    /// # // Create symmetric key object attributes
    /// # let symmetric_key_object_attributes = ObjectAttributesBuilder::new()
    /// #     .with_user_with_auth(true)
    /// #     .with_sign_encrypt(true)
    /// #     .with_decrypt(true)
    /// #     .build()
    /// #     .expect("Failed to create object attributes for symmetric key");
    /// # // Create public part for the symmetric key
    /// # let symmetric_key_public = PublicBuilder::new()
    /// #     .with_public_algorithm(PublicAlgorithm::SymCipher)
    /// #     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_object_attributes(symmetric_key_object_attributes)
    /// #     .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(SymmetricDefinitionObject::AES_256_CFB))
    /// #     .with_symmetric_cipher_unique_identifier(Default::default())
    /// #     .build()
    /// #     .expect("Failed to create public for symmetric key public");
    /// # // Create auth for the symmetric key
    /// # let mut random_digest = vec![0u8; 16];
    /// # getrandom::fill(&mut random_digest).expect("get_rand call failed");
    /// # let symmetric_key_auth = Auth::try_from(
    /// #     random_digest
    /// # )
    /// # .expect("Failed to create symmetric key auth");
    /// # // Create symmetric key data
    /// # let symmetric_key_value =
    /// #     SensitiveData::try_from(vec![
    /// #           1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
    /// #           17, 18, 19, 20, 21, 22 ,23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
    /// #           .expect("Failed to create sensitive data from data");
    /// # // Create the symmetric key
    /// # // if this fails with "tpm:parameter(2):inconsistent attributes" then the symmetric
    /// # // cipher is probably not supported.
    /// # let symmetric_key_creation_data =
    /// #     context.execute_with_session(Some(AuthSession::Password), |ctx| {
    /// #         ctx.create(
    /// #             primary_key_handle,
    /// #             symmetric_key_public,
    /// #             Some(symmetric_key_auth.clone()),
    /// #             Some(symmetric_key_value),
    /// #             None,
    /// #             None,
    /// #         )
    /// #         .expect("Failed to create symmetric key")
    /// #     });
    /// # // Load the symmetric key in order to get handle to it.
    /// # let symmetric_key_handle =
    /// #     context.execute_with_session(Some(AuthSession::Password), |ctx| {
    /// #         ctx.load(
    /// #             primary_key_handle,
    /// #             symmetric_key_creation_data.out_private,
    /// #             symmetric_key_creation_data.out_public,
    /// #         )
    /// #         .expect("Failed to load symmetric key")
    /// #     });
    /// # // Set auth for the handle to be able to use it.
    /// # context
    /// #     .tr_set_auth(symmetric_key_handle.into(), symmetric_key_auth)
    /// #     .expect("Failed to set auth on symmetric key handle");
    /// #
    /// # // Create initial value to be used by the algorithm.
    /// # let initial_value =
    /// # InitialValue::try_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    /// #    .expect("Failed to create InitialValue from data");
    /// # // Create data to be encrypted.
    /// # let data = MaxBuffer::try_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16])
    /// #    .expect("Failed to create MaxBuffer from data");
    /// // Encrypt the data
    /// let (encrypted_data, _initial_value_out) =
    ///     context.execute_with_session(Some(AuthSession::Password), |ctx| {
    ///         ctx.encrypt_decrypt_2(
    ///             symmetric_key_handle, // Handle to a symmetric key
    ///             false,                // false, indicates that the data should be encrypted.
    ///             SymmetricMode::Cfb,   // The symmetric mode of the encryption.
    ///             data.clone(),                // The data that is to be encrypted.
    ///             initial_value.clone(),       // Initial value needed by the algorithm.
    ///         )
    ///         .expect("Call to encrypt_decrypt_2 failed when encrypting data")
    ///     });
    ///
    /// assert_ne!(data.clone(), encrypted_data);
    /// #
    /// # let (decrypted_data, _) =
    /// #     context.execute_with_session(Some(AuthSession::Password), |ctx| {
    /// #         ctx.encrypt_decrypt_2(
    /// #             symmetric_key_handle,
    /// #             true,
    /// #             SymmetricMode::Cfb,
    /// #             encrypted_data,
    /// #             initial_value,
    /// #         )
    /// #         .expect("Call to encrypt_decrypt_2 failed when decrypting data")
    /// #     });
    /// #
    /// # debug_assert_eq!(data, decrypted_data);
    /// ```
    pub fn encrypt_decrypt_2(
        &mut self,
        key_handle: KeyHandle,
        decrypt: bool,
        mode: SymmetricMode,
        in_data: MaxBuffer,
        initial_value_in: InitialValue,
    ) -> Result<(MaxBuffer, InitialValue)> {
        let mut out_data_ptr = null_mut();
        let mut iv_out_ptr = null_mut();
        let ret = unsafe {
            Esys_EncryptDecrypt2(
                self.mut_context(),
                key_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                &in_data.into(),
                decrypt.into(),
                mode.into(),
                &initial_value_in.into(),
                &mut out_data_ptr,
                &mut iv_out_ptr,
            )
        };

        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok((
                MaxBuffer::try_from(Context::ffi_data_to_owned(out_data_ptr))?,
                InitialValue::try_from(Context::ffi_data_to_owned(iv_out_ptr))?,
            ))
        } else {
            error!(
                "Error failed to perform encrypt or decrypt operations {}",
                ret
            );
            Err(ret)
        }
    }

    /// Hashes the provided data using the specified algorithm.
    ///
    /// # Details
    /// Performs the specified hash operation on a data buffer and return
    /// the result. The HashCheckTicket indicates if the hash can be used in
    /// a signing operation that uses restricted signing key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, tcti_ldr::TctiNameConf,
    /// #     structures::{MaxBuffer, Ticket},
    /// #     interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
    /// # };
    /// # use std::convert::TryFrom;
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let input_data = MaxBuffer::try_from("There is no spoon".as_bytes().to_vec())
    ///     .expect("Failed to create buffer for input data.");
    /// let expected_hashed_data: [u8; 32] = [
    ///     0x6b, 0x38, 0x4d, 0x2b, 0xfb, 0x0e, 0x0d, 0xfb, 0x64, 0x89, 0xdb, 0xf4, 0xf8, 0xe9,
    ///     0xe5, 0x2f, 0x71, 0xee, 0xb1, 0x0d, 0x06, 0x4c, 0x56, 0x59, 0x70, 0xcd, 0xd9, 0x44,
    ///     0x43, 0x18, 0x5d, 0xc1,
    /// ];
    /// let expected_hierarchy = Hierarchy::Owner;
    /// let (actual_hashed_data, ticket) = context
    ///     .hash(
    ///         input_data,
    ///         HashingAlgorithm::Sha256,
    ///         expected_hierarchy,
    ///     )
    ///     .expect("Call to hash failed.");
    /// assert_eq!(expected_hashed_data.len(), actual_hashed_data.len());
    /// assert_eq!(&expected_hashed_data[..], &actual_hashed_data[..]);
    /// assert_eq!(ticket.hierarchy(), expected_hierarchy);
    /// ```
    pub fn hash(
        &mut self,
        data: MaxBuffer,
        hashing_algorithm: HashingAlgorithm,
        hierarchy: Hierarchy,
    ) -> Result<(Digest, HashcheckTicket)> {
        let mut out_hash_ptr = null_mut();
        let mut validation_ptr = null_mut();
        let ret = unsafe {
            #[allow(unexpected_cfgs)]
            Esys_Hash(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &data.into(),
                hashing_algorithm.into(),
                if cfg!(tpm2_tss_version = "2") {
                    TpmHandle::from(hierarchy).into()
                } else {
                    ObjectHandle::from(hierarchy).into()
                },
                &mut out_hash_ptr,
                &mut validation_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok((
                Digest::try_from(Context::ffi_data_to_owned(out_hash_ptr))?,
                HashcheckTicket::try_from(Context::ffi_data_to_owned(validation_ptr))?,
            ))
        } else {
            error!("Error failed to perform hash operation: {}", ret);
            Err(ret)
        }
    }

    /// Asks the TPM to compute an HMAC over buffer with the specified key
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #     attributes::ObjectAttributesBuilder,
    /// #     structures::{MaxBuffer, Ticket, PublicKeyedHashParameters, KeyedHashScheme, HmacScheme, PublicBuilder, Digest},
    /// #     interface_types::{
    /// #           resource_handles::Hierarchy,
    /// #           algorithm::{HashingAlgorithm, PublicAlgorithm},
    /// #     },
    /// #     Context, tcti_ldr::TctiNameConf,
    /// # };
    /// # use std::convert::TryFrom;
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// // Create a key
    /// let object_attributes = ObjectAttributesBuilder::new()
    ///     .with_sign_encrypt(true)
    ///     .with_sensitive_data_origin(true)
    ///     .with_user_with_auth(true)
    ///     .build()
    ///     .expect("Failed to build object attributes");
    /// let key_pub = PublicBuilder::new()
    ///     .with_public_algorithm(PublicAlgorithm::KeyedHash)
    ///     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    ///     .with_object_attributes(object_attributes)
    ///     .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::HMAC_SHA_256))
    ///     .with_keyed_hash_unique_identifier(Digest::default())
    ///     .build()
    ///     .unwrap();
    ///
    /// let input_data = MaxBuffer::try_from("There is no spoon".as_bytes().to_vec())
    ///     .expect("Failed to create buffer for input data.");
    ///
    /// let hmac = context.execute_with_nullauth_session(|ctx| {
    ///     let key = ctx.create_primary(Hierarchy::Owner, key_pub, None, None, None, None).unwrap();
    ///
    ///     ctx.hmac(key.key_handle.into(), input_data, HashingAlgorithm::Sha256)
    /// }).unwrap();
    ///
    /// ```
    ///
    /// # Errors
    /// * if any of the public parameters is not compatible with the TPM,
    ///   an `Err` containing the specific unmarshalling error will be returned.
    pub fn hmac(
        &mut self,
        handle: ObjectHandle,
        buffer: MaxBuffer,
        alg_hash: HashingAlgorithm,
    ) -> Result<Digest> {
        let mut out_hmac_ptr = null_mut();
        let ret = unsafe {
            Esys_HMAC(
                self.mut_context(),
                handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                &buffer.into(),
                alg_hash.into(),
                &mut out_hmac_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            Digest::try_from(Context::ffi_data_to_owned(out_hmac_ptr))
        } else {
            error!("Error in hmac: {}", ret);
            Err(ret)
        }
    }

    // Missing function: MAC
}
