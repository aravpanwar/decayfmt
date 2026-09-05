// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::KeyHandle,
    structures::Data,
    structures::{EccPoint, PublicKeyRsa, RsaDecryptionScheme},
    tss2_esys::{Esys_ECDH_KeyGen, Esys_ECDH_ZGen, Esys_RSA_Decrypt, Esys_RSA_Encrypt},
    Context, Error, Result,
};
use log::error;
use std::convert::TryFrom;
use std::ptr::null_mut;

impl Context {
    /// Perform an asymmetric RSA encryption.
    pub fn rsa_encrypt(
        &mut self,
        key_handle: KeyHandle,
        message: PublicKeyRsa,
        in_scheme: RsaDecryptionScheme,
        label: Data,
    ) -> Result<PublicKeyRsa> {
        let mut out_data_ptr = null_mut();
        let ret = unsafe {
            Esys_RSA_Encrypt(
                self.mut_context(),
                key_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &message.into(),
                &in_scheme.into(),
                &label.into(),
                &mut out_data_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            PublicKeyRsa::try_from(Context::ffi_data_to_owned(out_data_ptr))
        } else {
            error!("Error when performing RSA encryption: {}", ret);
            Err(ret)
        }
    }

    /// Perform an asymmetric RSA decryption.
    pub fn rsa_decrypt(
        &mut self,
        key_handle: KeyHandle,
        cipher_text: PublicKeyRsa,
        in_scheme: RsaDecryptionScheme,
        label: Data,
    ) -> Result<PublicKeyRsa> {
        let mut message_ptr = null_mut();
        let ret = unsafe {
            Esys_RSA_Decrypt(
                self.mut_context(),
                key_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                &cipher_text.into(),
                &in_scheme.into(),
                &label.into(),
                &mut message_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            PublicKeyRsa::try_from(Context::ffi_data_to_owned(message_ptr))
        } else {
            error!("Error when performing RSA decryption: {}", ret);
            Err(ret)
        }
    }

    /// Generate an ephemeral key pair.
    ///
    /// # Arguments
    /// * `key_handle`- A [KeyHandle] of ECC key which curve parameters will be used
    ///   to generate the ephemeral key.
    ///
    /// # Details
    /// This command uses the TPM to generate an ephemeral
    /// key pair. It uses the private ephemeral key and a loaded
    /// public key to compute the shared secret value.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    attributes::{SessionAttributesBuilder, ObjectAttributesBuilder},
    /// #    constants::SessionType,
    /// #    interface_types::{
    /// #        algorithm::{
    /// #            HashingAlgorithm, PublicAlgorithm, RsaDecryptAlgorithm,
    /// #        },
    /// #        ecc::EccCurve,
    /// #        resource_handles::Hierarchy,
    /// #   },
    /// #   structures::{
    /// #       Auth, Data, EccScheme, PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, KeyDerivationFunctionScheme, EccPoint,
    /// #        RsaDecryptionScheme, HashScheme, SymmetricDefinition,
    /// #    },
    /// # };
    /// # use std::{env, str::FromStr, convert::TryFrom};
    /// # // Create context
    /// # let mut context =
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
    /// #         tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Received invalid handle");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// # let mut random_digest = vec![0u8; 16];
    /// # getrandom::fill(&mut random_digest).unwrap();
    /// # let key_auth = Auth::try_from(random_digest).unwrap();
    /// #
    /// // Create a key suitable for ECDH key generation
    /// let ecc_parms = PublicEccParametersBuilder::new()
    ///     .with_ecc_scheme(
    ///         EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)),
    ///     )
    ///     .with_curve(EccCurve::NistP256)
    ///     .with_is_signing_key(false)
    ///     .with_is_decryption_key(true)
    ///     .with_restricted(false)
    ///     .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
    ///     .build()
    ///     .unwrap();
    ///
    /// let object_attributes = ObjectAttributesBuilder::new()
    ///     .with_fixed_tpm(true)
    ///     .with_fixed_parent(true)
    ///     .with_sensitive_data_origin(true)
    ///     .with_user_with_auth(true)
    ///     .with_decrypt(true)
    ///     .with_sign_encrypt(false)
    ///     .with_restricted(false)
    ///     .build()
    ///     .unwrap();
    ///
    /// let public = PublicBuilder::new()
    ///     .with_public_algorithm(PublicAlgorithm::Ecc)
    ///     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    ///     .with_object_attributes(object_attributes)
    ///     .with_ecc_parameters(ecc_parms)
    ///     .with_ecc_unique_identifier(EccPoint::default())
    ///     .build()
    ///     .unwrap();
    ///
    /// let key_handle = context
    ///     .create_primary(
    ///         Hierarchy::Owner,
    ///         public,
    ///         Some(key_auth),
    ///         None,
    ///         None,
    ///         None,
    ///     )
    ///     .unwrap()
    ///     .key_handle;
    ///
    /// // Generate ephemeral key pair and a shared secret
    /// let (z_point, pub_point) = context.ecdh_key_gen(key_handle).unwrap();
    /// ```
    pub fn ecdh_key_gen(&mut self, key_handle: KeyHandle) -> Result<(EccPoint, EccPoint)> {
        let mut z_point_ptr = null_mut();
        let mut pub_point_ptr = null_mut();
        let ret = unsafe {
            Esys_ECDH_KeyGen(
                self.mut_context(),
                key_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &mut z_point_ptr,
                &mut pub_point_ptr,
            )
        };

        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let z_point = Context::ffi_data_to_owned(z_point_ptr);
            let pub_point = Context::ffi_data_to_owned(pub_point_ptr);
            Ok((
                EccPoint::try_from(z_point.point)?,
                EccPoint::try_from(pub_point.point)?,
            ))
        } else {
            error!("Error when generating ECDH keypair: {}", ret);
            Err(ret)
        }
    }

    /// Recover Z value from a public point and a private key.
    ///
    /// # Arguments
    /// * `key_handle` - A [KeyHandle] of ECC key which curve parameters will be used
    ///   to generate the ephemeral key.
    /// * `in_point` - An [EccPoint] on the curve of the key referenced by `key_handle`
    ///
    /// # Details
    /// This command uses the TPM to recover the Z value from a public point and a private key.
    /// It will perform the multiplication of the provided `in_point` with the private key and
    /// return the coordinates of the resultant point.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    attributes::{SessionAttributesBuilder, ObjectAttributesBuilder},
    /// #    constants::SessionType,
    /// #    interface_types::{
    /// #        algorithm::{
    /// #            HashingAlgorithm, PublicAlgorithm, RsaDecryptAlgorithm,
    /// #        },
    /// #        ecc::EccCurve,
    /// #        resource_handles::Hierarchy,
    /// #   },
    /// #   structures::{
    /// #       Auth, Data, EccScheme, PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, KeyDerivationFunctionScheme, EccPoint,
    /// #        RsaDecryptionScheme, HashScheme, SymmetricDefinition,
    /// #    },
    /// # };
    /// # use std::{env, str::FromStr, convert::TryFrom};
    /// # // Create context
    /// # let mut context =
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
    /// #         tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Received invalid handle");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// # let mut random_digest = vec![0u8; 16];
    /// # getrandom::fill(&mut random_digest).unwrap();
    /// # let key_auth = Auth::try_from(random_digest).unwrap();
    /// #
    /// // Create a key suitable for ECDH key generation
    /// let ecc_parms = PublicEccParametersBuilder::new()
    ///     .with_ecc_scheme(
    ///         EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)),
    ///     )
    ///     .with_curve(EccCurve::NistP256)
    ///     .with_is_signing_key(false)
    ///     .with_is_decryption_key(true)
    ///     .with_restricted(false)
    ///     .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
    ///     .build()
    ///     .unwrap();
    ///
    /// let object_attributes = ObjectAttributesBuilder::new()
    ///     .with_fixed_tpm(true)
    ///     .with_fixed_parent(true)
    ///     .with_sensitive_data_origin(true)
    ///     .with_user_with_auth(true)
    ///     .with_decrypt(true)
    ///     .with_sign_encrypt(false)
    ///     .with_restricted(false)
    ///     .build()
    ///     .unwrap();
    ///
    /// let public = PublicBuilder::new()
    ///     .with_public_algorithm(PublicAlgorithm::Ecc)
    ///     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    ///     .with_object_attributes(object_attributes)
    ///     .with_ecc_parameters(ecc_parms)
    ///     .with_ecc_unique_identifier(EccPoint::default())
    ///     .build()
    ///     .unwrap();
    ///
    /// let key_handle = context
    ///     .create_primary(
    ///         Hierarchy::Owner,
    ///         public,
    ///         Some(key_auth),
    ///         None,
    ///         None,
    ///         None,
    ///     )
    ///     .unwrap()
    ///     .key_handle;
    ///
    /// // Generate ephemeral key pair and a shared secret
    /// let (z_point, pub_point) = context.ecdh_key_gen(key_handle).unwrap();
    /// let z_point_gen = context.ecdh_z_gen(key_handle, pub_point).unwrap();
    /// assert_eq!(z_point.x().value(), z_point_gen.x().value());
    /// ```
    pub fn ecdh_z_gen(&mut self, key_handle: KeyHandle, in_point: EccPoint) -> Result<EccPoint> {
        let mut out_point_ptr = null_mut();
        let ret = unsafe {
            Esys_ECDH_ZGen(
                self.mut_context(),
                key_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                &in_point.into(),
                &mut out_point_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let out_point = Context::ffi_data_to_owned(out_point_ptr);
            EccPoint::try_from(out_point.point)
        } else {
            error!("Error when performing ECDH ZGen: {}", ret);
            Err(ret)
        }
    }

    // Missing function: ECC_Parameters
    // Missing function: ZGen_2Phase
}
