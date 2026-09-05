// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Module for abstracting resource handle management
//!
//! This module presents an abstraction over the TPM functionality exposed through the core
//! `Context` structure. The abstraction works by hiding resource handle management from the
//! client.
use crate::{
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{tss::*, SessionType, Tss2ResponseCodeKind},
    handles::{KeyHandle, ObjectHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        Auth, CreateKeyResult, Data, Digest, EccPoint, EccScheme, Name, Public, PublicBuilder,
        PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent,
        RsaScheme, Signature, SignatureScheme, SymmetricDefinitionObject, VerifiedTicket,
    },
    tcti_ldr::TctiNameConf,
    tss2_esys::*,
    utils::{create_restricted_decryption_rsa_public, PublicKey, TpmsContext},
    Context, Error, Result, WrapperErrorKind as ErrorKind,
};

use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::{AsMut, AsRef, TryFrom, TryInto};
use zeroize::Zeroize;

mod key_attestation;

pub use key_attestation::MakeCredParams;

/// Parameters for the kinds of keys supported by the context
#[derive(Debug, Clone, Copy)]
pub enum KeyParams {
    Rsa {
        /// Size of key in bits
        ///
        /// Can only be one of: 1024, 2048, 3072 or 4096
        size: RsaKeyBits,
        /// Asymmetric scheme to be used with the key
        scheme: RsaScheme,
        /// Public exponent of the key
        ///
        /// If set to 0, it will default to 2^16 - 1.
        ///
        /// (Note that the default value for [`RsaExponent`] is 0)
        pub_exponent: RsaExponent,
    },
    Ecc {
        /// Curve that the key will be based on
        curve: EccCurve,
        /// Asymmetric scheme to be used with the key
        scheme: EccScheme,
    },
}

/// Structure representing a key created or stored in the TPM
///
/// The `public` field represents the public part of the key in plain text,
/// while `private` is the encrypted version of the private key.
///
/// For information on public key formats, see the documentation of [`PublicKey`].
/// The private part of the key should be treated as an opaque binary blob.
///
/// # Warning
///
/// If the Owner hierarchy is cleared, any key material generated
/// prior to that event will become unusable.
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize)]
pub struct KeyMaterial {
    public: PublicKey,
    private: Vec<u8>,
}

impl KeyMaterial {
    /// Get a reference to the public part of the key
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Get a reference to the private part of the key
    pub fn private(&self) -> &[u8] {
        &self.private
    }
}

/// Structure containing all the defining elements of a TPM key
///
/// - `material` identifies the numeric value of the key object
/// - `params` identifies the algorithm to use on the key and other relevant parameters
/// - `auth` identifies the optional authentication value to be used with the key
#[derive(Debug, Clone)]
pub struct ObjectWrapper {
    pub material: KeyMaterial,
    pub params: KeyParams,
    pub auth: Option<Auth>,
}

/// Structure offering an abstracted programming experience.
///
/// The `TransientKeyContext` makes use of a root key from which the other, client-controlled
/// keys are derived.
///
/// This abstraction makes public key cryptography more accessible, focusing on asymmetric
/// encryption and signatures in particular, by allowing users to offload object and session management.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct TransientKeyContext {
    context: Context,
    root_key_handle: KeyHandle,
}

impl TransientKeyContext {
    /// Create a new key.
    ///
    /// A key is created as a descendant of the context root key, with the given parameters.
    ///
    /// If successful, the result contains the [KeyMaterial] of the key and a vector of
    /// bytes forming the authentication value for said key.
    ///
    /// The following key attributes are always **set**: `fixed_tpm`, `fixed_parent`, `sensitive_data_origin`,
    /// `user_with_auth`. The `restricted` attribute is **not set**. See section 8.3 in the Structures
    /// spec for a detailed description of these attributes.
    ///
    /// # Constraints
    /// * `auth_size` must be at most 32
    ///
    /// # Errors
    /// * if the authentication size is larger than 32 a `WrongParamSize` wrapper error is returned
    /// * if there is an error when obtaining random numbers from the local machine
    pub fn create_key(
        &mut self,
        key_params: KeyParams,
        auth_size: usize,
    ) -> Result<(KeyMaterial, Option<Auth>)> {
        if auth_size > 32 {
            return Err(Error::local_error(ErrorKind::WrongParamSize));
        }
        let key_auth = if auth_size > 0 {
            self.set_session_attrs()?;
            let mut random_bytes = vec![0u8; auth_size];
            getrandom::fill(&mut random_bytes).map_err(|_| {
                log::error!("Failed to obtain a random authvalue for key creation");
                Error::WrapperError(ErrorKind::InternalError)
            })?;
            Some(Auth::try_from(random_bytes)?)
        } else {
            None
        };

        self.set_session_attrs()?;
        let CreateKeyResult {
            out_private,
            out_public,
            ..
        } = self.context.create(
            self.root_key_handle,
            TransientKeyContext::get_public_from_params(key_params, None)?,
            key_auth.clone(),
            None,
            None,
            None,
        )?;

        let key_material = KeyMaterial {
            public: out_public.try_into()?,
            private: out_private.value().to_vec(),
        };
        Ok((key_material, key_auth))
    }

    /// Load the public part of a key.
    ///
    /// Returns the appropriate key material after verifying that the key can be loaded.
    pub fn load_external_public_key(
        &mut self,
        public_key: PublicKey,
        params: KeyParams,
    ) -> Result<KeyMaterial> {
        let public = TransientKeyContext::get_public_from_params(params, Some(public_key.clone()))?;
        self.set_session_attrs()?;
        let key_handle = self
            .context
            .load_external_public(public, Hierarchy::Owner)?;
        self.context.flush_context(key_handle.into())?;
        Ok(KeyMaterial {
            public: public_key,
            private: vec![],
        })
    }

    /// Encrypt a message with an existing key.
    ///
    /// Takes the key as a set of parameters (`key_material`, `key_params`, `key_auth`), encrypts the message
    /// and returns the ciphertext. A label can also be provided which will be associated with the ciphertext.
    ///
    /// Note: the data passed as `label` MUST end in a `0x00` byte.
    pub fn rsa_encrypt(
        &mut self,
        key_material: KeyMaterial,
        key_params: KeyParams,
        key_auth: Option<Auth>,
        message: PublicKeyRsa,
        label: Option<Data>,
    ) -> Result<PublicKeyRsa> {
        let key_handle = self.load_key(key_params, key_material, key_auth)?;
        let decrypt_scheme = if let KeyParams::Rsa { scheme, .. } = key_params {
            scheme.try_into()?
        } else {
            return Err(Error::local_error(ErrorKind::InvalidParam));
        };

        self.set_session_attrs()?;
        let ciphertext = self
            .context
            .rsa_encrypt(
                key_handle,
                message,
                decrypt_scheme,
                label.unwrap_or_default(),
            )
            .or_else(|e| {
                self.context.flush_context(key_handle.into())?;
                Err(e)
            })?;

        self.context.flush_context(key_handle.into())?;

        Ok(ciphertext)
    }

    /// Decrypt ciphertext with an existing key.
    ///
    /// Takes the key as a set of parameters (`key_material`, `key_params`, `key_auth`), decrypts the ciphertext
    /// and returns the plaintext. A label which was associated with the ciphertext can also be provided.
    ///
    /// Note: the data passed as `label` MUST end in a `0x00` byte.
    pub fn rsa_decrypt(
        &mut self,
        key_material: KeyMaterial,
        key_params: KeyParams,
        key_auth: Option<Auth>,
        ciphertext: PublicKeyRsa,
        label: Option<Data>,
    ) -> Result<PublicKeyRsa> {
        let key_handle = self.load_key(key_params, key_material, key_auth)?;
        let decrypt_scheme = if let KeyParams::Rsa { scheme, .. } = key_params {
            scheme.try_into()?
        } else {
            return Err(Error::local_error(ErrorKind::InvalidParam));
        };

        self.set_session_attrs()?;
        let plaintext = self
            .context
            .rsa_decrypt(
                key_handle,
                ciphertext,
                decrypt_scheme,
                label.unwrap_or_default(),
            )
            .or_else(|e| {
                self.context.flush_context(key_handle.into())?;
                Err(e)
            })?;

        self.context.flush_context(key_handle.into())?;

        Ok(plaintext)
    }

    /// Sign a digest with an existing key.
    ///
    /// Takes the key as a set of parameters (`key_material`, `key_params`, `key_auth`), signs and returns the signature.
    pub fn sign(
        &mut self,
        key_material: KeyMaterial,
        key_params: KeyParams,
        key_auth: Option<Auth>,
        digest: Digest,
    ) -> Result<Signature> {
        let key_handle = self.load_key(key_params, key_material, key_auth)?;

        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        self.set_session_attrs()?;
        let signature = self
            .context
            .sign(
                key_handle,
                digest,
                SignatureScheme::Null,
                validation.try_into()?,
            )
            .or_else(|e| {
                self.context.flush_context(key_handle.into())?;
                Err(e)
            })?;
        self.context.flush_context(key_handle.into())?;
        Ok(signature)
    }

    /// Verify a signature against a digest.
    ///
    /// Given a digest, a key and a signature, this method returns a `Verified` ticket if the
    /// verification was successful.
    ///
    /// # Errors
    /// * if the verification fails (i.e. the signature is invalid), a TPM error is returned
    pub fn verify_signature(
        &mut self,
        key_material: KeyMaterial,
        key_params: KeyParams,
        digest: Digest,
        signature: Signature,
    ) -> Result<VerifiedTicket> {
        let key_handle = self.load_key(key_params, key_material, None)?;

        self.set_session_attrs()?;
        let verified = self
            .context
            .verify_signature(key_handle, digest, signature)
            .or_else(|e| {
                self.context.flush_context(key_handle.into())?;
                Err(e)
            })?;
        self.context.flush_context(key_handle.into())?;
        Ok(verified)
    }

    /// Perform a migration from the previous version of the TransientKeyContext.
    ///
    /// The original version of the TransientKeyContext used contexts of keys for
    /// persistence. This method allows a key persisted in this way to be migrated
    /// to the new format.
    ///
    /// The method determines on its own whether the loaded key was a keypair or
    /// just a public key.
    pub fn migrate_key_from_ctx(
        &mut self,
        context: TpmsContext,
        auth: Option<Auth>,
    ) -> Result<KeyMaterial> {
        self.set_session_attrs()?;
        let key_handle = self.context.context_load(context).map(KeyHandle::from)?;
        if let Some(key_auth_value) = auth.clone() {
            self.context
                .tr_set_auth(key_handle.into(), key_auth_value)
                .or_else(|e| {
                    self.context.flush_context(key_handle.into())?;
                    Err(e)
                })?;
        }

        let (public, _, _) = self.context.read_public(key_handle).or_else(|e| {
            self.context.flush_context(key_handle.into())?;
            Err(e)
        })?;
        let private = self
            .context
            .object_change_auth(
                key_handle.into(),
                self.root_key_handle.into(),
                auth.unwrap_or_default(),
            )
            .or_else(|e| {
                if let Error::Tss2Error(resp_code) = e {
                    // If we get `AuthUnavailable` it means the private part of the key has not been
                    // loaded, and this is thus a public key
                    if resp_code.kind() == Some(Tss2ResponseCodeKind::AuthUnavailable) {
                        return Ok(Default::default());
                    }
                }
                error!("Getting private part of key failed.");
                self.context.flush_context(key_handle.into())?;
                Err(e)
            })?;

        let key_material = KeyMaterial {
            public: public.try_into()?,
            private: private.value().to_vec(),
        };

        self.context.flush_context(key_handle.into())?;
        Ok(key_material)
    }

    /// Gets the name of the root key of the TransientKeyContext
    pub fn get_root_key_name(&mut self) -> Result<Name> {
        let obj_handle: ObjectHandle = self.root_key_handle.into();
        self.context.tr_get_name(obj_handle)
    }

    /// Sets the encrypt and decrypt flags on the main session used by the context.
    ///
    /// # Errors
    /// * if `Context::set_session_attr` returns an error, that error is propagated through
    fn set_session_attrs(&mut self) -> Result<()> {
        if let (Some(session), _, _) = self.context.sessions() {
            let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
            self.context.tr_sess_set_attributes(
                session,
                session_attributes,
                session_attributes_mask,
            )?;
        }
        Ok(())
    }

    /// Given the parameters for an asymmetric key, return its [Public] structure
    ///
    /// The public part of the key can optionally be inserted in the structure.
    ///
    /// # Errors
    /// * if the public key and the parameters don't match, `InconsistentParams` is returned
    fn get_public_from_params(params: KeyParams, pub_key: Option<PublicKey>) -> Result<Public> {
        let decrypt_flag = matches!(
            params,
            KeyParams::Rsa {
                scheme: RsaScheme::RsaEs,
                ..
            } | KeyParams::Rsa {
                scheme: RsaScheme::Oaep(..),
                ..
            }
        );
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(decrypt_flag)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()?;

        let mut pub_builder = PublicBuilder::new()
            .with_public_algorithm(match params {
                KeyParams::Ecc { .. } => PublicAlgorithm::Ecc,
                KeyParams::Rsa { .. } => PublicAlgorithm::Rsa,
            })
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes);
        match params {
            KeyParams::Rsa {
                size,
                scheme,
                pub_exponent,
            } => {
                let unique = pub_key
                    .map(|pub_key| {
                        if let PublicKey::Rsa(val) = pub_key {
                            PublicKeyRsa::try_from(val)
                        } else {
                            Err(Error::local_error(ErrorKind::InconsistentParams))
                        }
                    })
                    .transpose()?
                    .unwrap_or_default();
                pub_builder = pub_builder
                    .with_rsa_parameters(
                        PublicRsaParametersBuilder::new()
                            .with_scheme(match scheme {
                                RsaScheme::RsaSsa { .. } | RsaScheme::RsaPss { .. } => scheme,
                                _ => RsaScheme::Null,
                            })
                            .with_key_bits(size)
                            .with_exponent(pub_exponent)
                            .with_is_signing_key(true)
                            .with_is_decryption_key(decrypt_flag)
                            .with_restricted(false)
                            .build()?,
                    )
                    .with_rsa_unique_identifier(unique);
            }
            KeyParams::Ecc { scheme, curve } => {
                let unique = pub_key
                    .map(|pub_key| {
                        if let PublicKey::Ecc { x, y } = pub_key {
                            Ok(EccPoint::new(x.try_into()?, y.try_into()?))
                        } else {
                            Err(Error::local_error(ErrorKind::InconsistentParams))
                        }
                    })
                    .transpose()?
                    .unwrap_or_default();
                pub_builder = pub_builder
                    .with_ecc_parameters(
                        PublicEccParametersBuilder::new_unrestricted_signing_key(scheme, curve)
                            .build()?,
                    )
                    .with_ecc_unique_identifier(unique);
            }
        }
        pub_builder.build()
    }

    /// Load a key into a TPM given its [KeyMaterial]
    ///
    /// If the key has only a public part, it is loaded accordingly in the Owner Hierarchy
    fn load_key(
        &mut self,
        params: KeyParams,
        material: KeyMaterial,
        auth: Option<Auth>,
    ) -> Result<KeyHandle> {
        let public = TransientKeyContext::get_public_from_params(params, Some(material.public))?;

        self.set_session_attrs()?;
        let key_handle = if material.private.is_empty() {
            self.context
                .load_external_public(public, Hierarchy::Owner)?
        } else {
            self.context
                .load(self.root_key_handle, material.private.try_into()?, public)?
        };
        let key_auth_value = auth.unwrap_or_default();
        if !key_auth_value.is_empty() {
            self.context
                .tr_set_auth(key_handle.into(), key_auth_value)
                .or_else(|e| {
                    self.context.flush_context(key_handle.into())?;
                    Err(e)
                })?;
        }
        Ok(key_handle)
    }

    /// Get a builder for the structure
    pub fn builder() -> TransientKeyContextBuilder {
        TransientKeyContextBuilder::new()
    }
}

impl AsRef<Context> for TransientKeyContext {
    fn as_ref(&self) -> &Context {
        &self.context
    }
}

impl AsMut<Context> for TransientKeyContext {
    fn as_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}

/// Build a new `TransientKeyContext`.
///
/// # Default values
/// * TCTI: Device TCTI
/// * Hierarchy: Owner hierarchy
/// * Root key size: 2048 bits
/// * Root key authentication size: 32 bytes
/// * Hierarchy authentication value: Empty array of bytes
/// * Session encryption cipher: 256 bit AES in CFB mode
/// * Session hash algorithm: SHA256
#[derive(Debug)]
pub struct TransientKeyContextBuilder {
    tcti_name_conf: TctiNameConf,
    root_key_size: u16, // TODO: replace with root key PUBLIC definition
    root_key_auth_size: usize,
    root_hierarchy: Hierarchy,
    hierarchy_auth: HashMap<Hierarchy, Vec<u8>>,
    default_context_cipher: SymmetricDefinitionObject,
    session_hash_alg: HashingAlgorithm,
}

impl TransientKeyContextBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        TransientKeyContextBuilder {
            tcti_name_conf: TctiNameConf::Device(Default::default()),
            root_hierarchy: Hierarchy::Owner,
            root_key_size: 2048,
            root_key_auth_size: 32,
            hierarchy_auth: HashMap::new(),
            default_context_cipher: SymmetricDefinitionObject::AES_256_CFB,
            session_hash_alg: HashingAlgorithm::Sha256,
        }
    }

    /// Define the TCTI name configuration to be used by the client.
    pub fn with_tcti(mut self, tcti_name_conf: TctiNameConf) -> Self {
        self.tcti_name_conf = tcti_name_conf;
        self
    }

    /// Set the auth values for any hierarchies that will be used
    pub fn with_hierarchy_auth(mut self, hierarchy: Hierarchy, auth: Vec<u8>) -> Self {
        let _ = self.hierarchy_auth.insert(hierarchy, auth);
        self
    }

    /// Define which hierarchy will be used for the keys being managed.
    pub fn with_root_hierarchy(mut self, hierarchy: Hierarchy) -> Self {
        self.root_hierarchy = hierarchy;
        self
    }

    /// Choose length in bits of primary key that will serve as parent to all user keys.
    pub fn with_root_key_size(mut self, root_key_size: u16) -> Self {
        self.root_key_size = root_key_size;
        self
    }

    /// Choose authentication value length (in bytes) for primary key.
    pub fn with_root_key_auth_size(mut self, root_key_auth_size: usize) -> Self {
        self.root_key_auth_size = root_key_auth_size;
        self
    }

    /// Define the cipher to be used within this context as a default.
    ///
    /// Currently this default is used for:
    /// * securing command parameters using session-based encryption
    /// * encrypting all user keys using the primary key
    pub fn with_default_context_cipher(
        mut self,
        default_context_cipher: SymmetricDefinitionObject,
    ) -> Self {
        self.default_context_cipher = default_context_cipher;
        self
    }

    /// Define the cipher to be used by sessions for hashing commands.
    pub fn with_session_hash_alg(mut self, session_hash_alg: HashingAlgorithm) -> Self {
        self.session_hash_alg = session_hash_alg;
        self
    }

    /// Bootstrap the TransientKeyContext.
    ///
    /// The root key is created as a primary key in the provided hierarchy and thus authentication is
    /// needed for said hierarchy. The authentication value for the key is generated locally in the machine,
    /// with a configurable length, and never exposed outside the context.
    ///
    /// # Warning
    /// It is the responsibility of the client to ensure that the context can be initialized
    /// safely, threading-wise by choosing the correct TCTI. See the Warning notice of the Context
    /// structure for more information.
    ///
    /// # Constraints
    /// * `root_key_size` must be 1024, 2048, 3072 or 4096
    /// * `root_key_auth_size` must be at most 32
    ///
    /// # Errors
    /// * errors are returned if any method calls return an error: `Context::start_auth_session`
    ///   `Context::create_primary`, `Context::flush_context`, `Context::set_handle_auth`
    ///   or if an internal error occurs when getting random numbers from the local machine
    /// * if the root key authentication size is given greater than 32 or if the root key size is
    ///   not 1024, 2048, 3072 or 4096, a `InvalidParam` wrapper error is returned
    pub fn build(mut self) -> Result<TransientKeyContext> {
        if self.root_key_auth_size > 32 {
            return Err(Error::local_error(ErrorKind::WrongParamSize));
        }

        let root_key_rsa_key_bits = RsaKeyBits::try_from(self.root_key_size)?;

        let mut context = Context::new(self.tcti_name_conf)?;

        let root_key_auth = if self.root_key_auth_size > 0 {
            let mut random = vec![0u8; self.root_key_auth_size];
            getrandom::fill(&mut random).map_err(|_| {
                log::error!("Failed to obtain a random value for root key authentication");
                Error::WrapperError(ErrorKind::InternalError)
            })?;
            Some(Auth::try_from(random)?)
        } else {
            None
        };

        for (hierarchy, auth) in self.hierarchy_auth.drain() {
            let auth_hierarchy = Auth::try_from(auth)?;
            context.tr_set_auth(hierarchy.into(), auth_hierarchy)?;
        }

        let session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                self.default_context_cipher.into(),
                self.session_hash_alg,
            )
            .and_then(|session| {
                session.ok_or_else(|| {
                    error!("Received unexpected NONE handle from the TPM");
                    Error::local_error(ErrorKind::WrongValueFromTpm)
                })
            })?;
        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)?;
        context.set_sessions((Some(session), None, None));

        let root_key_handle = context
            .create_primary(
                self.root_hierarchy,
                create_restricted_decryption_rsa_public(
                    self.default_context_cipher,
                    root_key_rsa_key_bits,
                    RsaExponent::ZERO_EXPONENT,
                )?,
                root_key_auth,
                None,
                None,
                None,
            )?
            .key_handle;

        let new_session_cipher = self.default_context_cipher;
        let new_session_hashing_algorithm = self.session_hash_alg;
        let new_session = context.execute_without_session(|ctx| {
            ctx.start_auth_session(
                Some(root_key_handle),
                None,
                None,
                SessionType::Hmac,
                new_session_cipher.into(),
                new_session_hashing_algorithm,
            )
            .and_then(|session| {
                session.ok_or_else(|| {
                    error!("Received unexpected NONE handle from the TPM");
                    Error::local_error(ErrorKind::WrongValueFromTpm)
                })
            })
        })?;
        if let (Some(old_session), _, _) = context.sessions() {
            context.set_sessions((Some(new_session), None, None));
            context.flush_context(SessionHandle::from(old_session).into())?;
        }
        Ok(TransientKeyContext {
            context,
            root_key_handle,
        })
    }
}

impl Default for TransientKeyContextBuilder {
    fn default() -> Self {
        TransientKeyContextBuilder::new()
    }
}
