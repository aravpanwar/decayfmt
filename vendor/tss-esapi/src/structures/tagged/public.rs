// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
pub mod ecc;
pub mod keyed_hash;
pub mod rsa;

use crate::{
    attributes::ObjectAttributes,
    interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm},
    structures::{
        Digest, EccPoint, PublicKeyRsa, SymmetricCipherParameters, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    tss2_esys::{TPM2B_PUBLIC, TPMT_PUBLIC},
    Error, Result, WrapperErrorKind,
};

use ecc::PublicEccParameters;
use keyed_hash::PublicKeyedHashParameters;
use rsa::PublicRsaParameters;

use log::error;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
};
use tss_esapi_sys::{TPMU_PUBLIC_ID, TPMU_PUBLIC_PARMS};

/// A builder for the [Public] type.
#[derive(Debug, Clone)]
pub struct PublicBuilder {
    public_algorithm: Option<PublicAlgorithm>,
    object_attributes: Option<ObjectAttributes>,
    name_hashing_algorithm: Option<HashingAlgorithm>,
    auth_policy: Option<Digest>,
    rsa_parameters: Option<PublicRsaParameters>,
    rsa_unique_identifier: Option<PublicKeyRsa>,
    keyed_hash_parameters: Option<PublicKeyedHashParameters>,
    keyed_hash_unique_identifier: Option<Digest>,
    ecc_parameters: Option<PublicEccParameters>,
    ecc_unique_identifier: Option<EccPoint>,
    symmetric_cipher_parameters: Option<SymmetricCipherParameters>,
    symmetric_cipher_unique_identifier: Option<Digest>,
}

impl PublicBuilder {
    /// Creates a new [PublicBuilder]
    ///
    /// # Details
    /// Builds the [Public] type using the provided parameters. Parameters
    /// associated with other algorithms then the provided public algorithm
    /// will be ignored.
    pub const fn new() -> Self {
        PublicBuilder {
            public_algorithm: None,
            object_attributes: None,
            name_hashing_algorithm: None,
            auth_policy: None,
            rsa_parameters: None,
            rsa_unique_identifier: None,
            keyed_hash_parameters: None,
            keyed_hash_unique_identifier: None,
            ecc_parameters: None,
            ecc_unique_identifier: None,
            symmetric_cipher_parameters: None,
            symmetric_cipher_unique_identifier: None,
        }
    }

    /// Adds the public algorithm for the [Public] structure
    /// to the builder.
    pub const fn with_public_algorithm(mut self, public_algorithm: PublicAlgorithm) -> Self {
        self.public_algorithm = Some(public_algorithm);
        self
    }

    /// Adds the attributes of the [Public] structure
    /// to the builder
    pub const fn with_object_attributes(mut self, object_attributes: ObjectAttributes) -> Self {
        self.object_attributes = Some(object_attributes);
        self
    }

    /// Adds the name hash algorithm for the [Public] structure
    /// to the builder.
    pub const fn with_name_hashing_algorithm(
        mut self,
        name_hashing_algorithm: HashingAlgorithm,
    ) -> Self {
        self.name_hashing_algorithm = Some(name_hashing_algorithm);
        self
    }

    /// Adds the auth policy for the [Public] structure
    /// to the builder
    pub fn with_auth_policy(mut self, auth_policy: Digest) -> Self {
        self.auth_policy = Some(auth_policy);
        self
    }

    /// Adds the RSA parameters for the [Public] structure
    /// to the builder.
    ///
    /// # Details
    /// This is required if the public algorithm is set to
    /// [Rsa][`crate::interface_types::algorithm::PublicAlgorithm::Rsa].
    pub fn with_rsa_parameters(mut self, rsa_parameters: PublicRsaParameters) -> Self {
        self.rsa_parameters = Some(rsa_parameters);
        self
    }

    /// Adds the RSA unique identifier for the [Public] structure
    /// to the builder.
    ///
    /// # Details
    /// This is required if the public algorithm is set to
    /// [Rsa][`crate::interface_types::algorithm::PublicAlgorithm::Rsa].
    ///
    /// The unique identifier is the public key.
    pub fn with_rsa_unique_identifier(mut self, rsa_unique_identifier: PublicKeyRsa) -> Self {
        self.rsa_unique_identifier = Some(rsa_unique_identifier);
        self
    }

    /// Adds the keyed hash parameters for the [Public] structure
    /// to the builder.
    ///
    /// # Details
    /// This is required if the public algorithm is set to
    /// [KeyedHash][`crate::interface_types::algorithm::PublicAlgorithm::KeyedHash].
    pub fn with_keyed_hash_parameters(
        mut self,
        keyed_hash_parameters: PublicKeyedHashParameters,
    ) -> Self {
        self.keyed_hash_parameters = Some(keyed_hash_parameters);
        self
    }

    /// Adds the keyed hash unique identifier for the [Public] structure
    /// to the builder.
    ///
    /// # Details
    /// This is required if the public algorithm is set to
    /// [KeyedHash][`crate::interface_types::algorithm::PublicAlgorithm::KeyedHash].
    pub fn with_keyed_hash_unique_identifier(
        mut self,
        keyed_hash_unique_identifier: Digest,
    ) -> Self {
        self.keyed_hash_unique_identifier = Some(keyed_hash_unique_identifier);
        self
    }

    /// Adds the ECC parameters for the [Public] structure
    /// to the builder.
    ///
    /// # Details
    /// This is required if the public algorithm is set to
    /// [Ecc][`crate::interface_types::algorithm::PublicAlgorithm::Ecc].
    pub const fn with_ecc_parameters(mut self, ecc_parameters: PublicEccParameters) -> Self {
        self.ecc_parameters = Some(ecc_parameters);
        self
    }

    /// Adds the ECC unique identifier for the [Public] structure
    /// to the builder.
    ///
    /// # Details
    /// This is required if the public algorithm is set to
    /// [Ecc][`crate::interface_types::algorithm::PublicAlgorithm::Ecc].
    ///
    /// The unique identifier is a ecc point.
    pub fn with_ecc_unique_identifier(mut self, ecc_unique_identifier: EccPoint) -> Self {
        self.ecc_unique_identifier = Some(ecc_unique_identifier);
        self
    }

    /// Adds the symmetric cipher parameters for the [Public] structure
    /// to the builder.
    ///
    /// # Details
    /// This is required if the public algorithm is set to
    /// [SymCipher][`crate::interface_types::algorithm::PublicAlgorithm::SymCipher].
    pub const fn with_symmetric_cipher_parameters(
        mut self,
        symmetric_cipher_parameters: SymmetricCipherParameters,
    ) -> Self {
        self.symmetric_cipher_parameters = Some(symmetric_cipher_parameters);
        self
    }

    /// Adds the symmetric cipher unique identifier for the [Public] structure
    /// to the builder.
    ///
    /// # Details
    /// This is required if the public algorithm is set to
    /// [SymCipher][`crate::interface_types::algorithm::PublicAlgorithm::SymCipher].
    pub fn with_symmetric_cipher_unique_identifier(
        mut self,
        symmetric_cipher_unique_identifier: Digest,
    ) -> Self {
        self.symmetric_cipher_unique_identifier = Some(symmetric_cipher_unique_identifier);
        self
    }

    /// Builds the [Public] structure.
    ///
    /// # Errors
    /// Will return error if the public algorithm, object attributes or name
    /// hashing algorithm have not been set or if the parameters and unique identifier
    /// does not match the selected public algorithm.
    pub fn build(self) -> Result<Public> {
        let algorithm = self.public_algorithm.ok_or_else(|| {
            error!("Algorithm is required and has not been set in the PublicBuilder");
            Error::local_error(WrapperErrorKind::ParamsMissing)
        })?;

        let object_attributes = self.object_attributes.ok_or_else(|| {
            error!("ObjectAttributes is required and has not been set in the PublicBuilder");
            Error::local_error(WrapperErrorKind::ParamsMissing)
        })?;

        let name_hashing_algorithm = self.name_hashing_algorithm.ok_or_else(|| {
            error!(
                "The name hashing algorithm is required and has not been set in the PublicBuilder"
            );
            Error::local_error(WrapperErrorKind::ParamsMissing)
        })?;

        let auth_policy = self.auth_policy.unwrap_or_default();

        match algorithm {
            PublicAlgorithm::Rsa => {
                Ok(Public::Rsa {
                    object_attributes,
                    name_hashing_algorithm,
                    auth_policy,
                    parameters: self.rsa_parameters.ok_or_else(|| {
                        error!("RSA parameters have not been set in the PublicBuilder even though the RSA algorithm had been selected.");
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })?,
                    unique: self.rsa_unique_identifier.ok_or_else(|| {
                        error!("RSA unique identifier has not been set in the PublicBuilder even though the RSA algorithm had been selected. Consider using: .with_rsa_unique_identifier(&PublicKeyRsa::default())");
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })?,
                })
            },
            PublicAlgorithm::KeyedHash => {
                Ok(Public::KeyedHash {
                    object_attributes,
                    name_hashing_algorithm,
                    auth_policy,
                    parameters: self.keyed_hash_parameters.ok_or_else(|| {
                        error!("Keyed hash parameters have not been set in the Public Builder even though the keyed hash algorithm have been selected");
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })?,
                    unique: self.keyed_hash_unique_identifier.ok_or_else(|| {
                        error!("Keyed hash unique identifier have not been set in the Public Builder even though the keyed hash algorithm have been selected. Consider using: .with_keyed_hash_unique_identifier(&Digest::default())");
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })?,
                })
            },
            PublicAlgorithm::Ecc => {
                Ok(Public::Ecc {
                    object_attributes,
                    name_hashing_algorithm,
                    auth_policy,
                    parameters: self.ecc_parameters.ok_or_else(|| {
                        error!("ECC parameters have not been set in the Public Builder even though the ECC algorithm have been selected");
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })?,
                    unique: self.ecc_unique_identifier.ok_or_else(|| {
                        error!("ECC unique identifier have not been set in the Public Builder even though the ECC algorithm have been selected. Consider using: .with_ecc_unique_identifier(&EccPoint::default())");
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })?,
                })
            }
            PublicAlgorithm::SymCipher => {
                Ok(Public::SymCipher {
                    object_attributes,
                    name_hashing_algorithm,
                    auth_policy,
                    parameters: self.symmetric_cipher_parameters.ok_or_else(|| {
                        error!("Symmetric cipher parameters have not been set in the Public Builder even though the symmetric cipher algorithm have been selected");
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })?,
                    unique: self.symmetric_cipher_unique_identifier.ok_or_else(|| {
                        error!("Symmetric cipher unique identifier have not been set in the Public Builder even though the symmetric cipher algorithm have been selected. Consider using: .with_symmetric_cipher_unique_identifier(&Digest::default())");
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })?,
                })
            }
        }
    }
}

impl Default for PublicBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Enum representing the Public structure.
///
/// # Details
/// This corresponds to TPMT_PUBLIC
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Public {
    Rsa {
        object_attributes: ObjectAttributes,
        name_hashing_algorithm: HashingAlgorithm,
        auth_policy: Digest,
        parameters: PublicRsaParameters,
        unique: PublicKeyRsa,
    },
    KeyedHash {
        object_attributes: ObjectAttributes,
        name_hashing_algorithm: HashingAlgorithm,
        auth_policy: Digest,
        parameters: PublicKeyedHashParameters,
        unique: Digest,
    },
    Ecc {
        object_attributes: ObjectAttributes,
        name_hashing_algorithm: HashingAlgorithm,
        auth_policy: Digest,
        parameters: PublicEccParameters,
        unique: EccPoint,
    },
    SymCipher {
        object_attributes: ObjectAttributes,
        name_hashing_algorithm: HashingAlgorithm,
        auth_policy: Digest,
        parameters: SymmetricCipherParameters,
        unique: Digest,
    },
}

impl Public {
    /// Returns the object attributes
    pub fn object_attributes(&self) -> ObjectAttributes {
        match self {
            Public::Rsa {
                object_attributes, ..
            }
            | Public::KeyedHash {
                object_attributes, ..
            }
            | Public::Ecc {
                object_attributes, ..
            }
            | Public::SymCipher {
                object_attributes, ..
            } => *object_attributes,
        }
    }

    /// Returns the name hashing algorithm
    pub fn name_hashing_algorithm(&self) -> HashingAlgorithm {
        match self {
            Public::Rsa {
                name_hashing_algorithm,
                ..
            }
            | Public::KeyedHash {
                name_hashing_algorithm,
                ..
            }
            | Public::Ecc {
                name_hashing_algorithm,
                ..
            }
            | Public::SymCipher {
                name_hashing_algorithm,
                ..
            } => *name_hashing_algorithm,
        }
    }

    /// Returns the name symmetric definition object if available.
    pub fn symmetric_algorithm(&self) -> Option<SymmetricDefinitionObject> {
        match self {
            Public::Rsa { parameters, .. } => Some(parameters.symmetric_definition_object()),
            Public::KeyedHash { .. } => None,
            Public::Ecc { parameters, .. } => Some(parameters.symmetric_definition_object()),
            Public::SymCipher { parameters, .. } => Some(parameters.symmetric_definition_object()),
        }
    }

    /// Returns the auth policy digest.
    pub fn auth_policy(&self) -> &Digest {
        match self {
            Public::Rsa { auth_policy, .. }
            | Public::KeyedHash { auth_policy, .. }
            | Public::Ecc { auth_policy, .. }
            | Public::SymCipher { auth_policy, .. } => auth_policy,
        }
    }

    /// Get a builder for this structure
    pub const fn builder() -> PublicBuilder {
        PublicBuilder::new()
    }
}

impl From<Public> for TPMT_PUBLIC {
    fn from(public: Public) -> Self {
        match public {
            Public::Rsa {
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
                unique,
            } => TPMT_PUBLIC {
                type_: PublicAlgorithm::Rsa.into(),
                nameAlg: name_hashing_algorithm.into(),
                objectAttributes: object_attributes.into(),
                authPolicy: auth_policy.into(),
                parameters: TPMU_PUBLIC_PARMS {
                    rsaDetail: parameters.into(),
                },
                unique: TPMU_PUBLIC_ID { rsa: unique.into() },
            },
            Public::KeyedHash {
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
                unique,
            } => TPMT_PUBLIC {
                type_: PublicAlgorithm::KeyedHash.into(),
                nameAlg: name_hashing_algorithm.into(),
                objectAttributes: object_attributes.into(),
                authPolicy: auth_policy.into(),
                parameters: TPMU_PUBLIC_PARMS {
                    keyedHashDetail: parameters.into(),
                },
                unique: TPMU_PUBLIC_ID {
                    keyedHash: unique.into(),
                },
            },
            Public::Ecc {
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
                unique,
            } => TPMT_PUBLIC {
                type_: PublicAlgorithm::Ecc.into(),
                nameAlg: name_hashing_algorithm.into(),
                objectAttributes: object_attributes.into(),
                authPolicy: auth_policy.into(),
                parameters: TPMU_PUBLIC_PARMS {
                    eccDetail: parameters.into(),
                },
                unique: TPMU_PUBLIC_ID { ecc: unique.into() },
            },
            Public::SymCipher {
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
                unique,
            } => TPMT_PUBLIC {
                type_: PublicAlgorithm::SymCipher.into(),
                nameAlg: name_hashing_algorithm.into(),
                objectAttributes: object_attributes.into(),
                authPolicy: auth_policy.into(),
                parameters: TPMU_PUBLIC_PARMS {
                    symDetail: parameters.into(),
                },
                unique: TPMU_PUBLIC_ID { sym: unique.into() },
            },
        }
    }
}

impl TryFrom<TPMT_PUBLIC> for Public {
    type Error = Error;

    fn try_from(tpmt_public: TPMT_PUBLIC) -> Result<Self> {
        match PublicAlgorithm::try_from(tpmt_public.type_)? {
            PublicAlgorithm::Rsa => Ok(Public::Rsa {
                object_attributes: tpmt_public.objectAttributes.into(),
                name_hashing_algorithm: tpmt_public.nameAlg.try_into()?,
                auth_policy: tpmt_public.authPolicy.try_into()?,
                parameters: unsafe { tpmt_public.parameters.rsaDetail }.try_into()?,
                unique: unsafe { tpmt_public.unique.rsa }.try_into()?,
            }),
            PublicAlgorithm::KeyedHash => Ok(Public::KeyedHash {
                object_attributes: tpmt_public.objectAttributes.into(),
                name_hashing_algorithm: tpmt_public.nameAlg.try_into()?,
                auth_policy: tpmt_public.authPolicy.try_into()?,
                parameters: unsafe { tpmt_public.parameters.keyedHashDetail }.try_into()?,
                unique: unsafe { tpmt_public.unique.keyedHash }.try_into()?,
            }),
            PublicAlgorithm::Ecc => Ok(Public::Ecc {
                object_attributes: tpmt_public.objectAttributes.into(),
                name_hashing_algorithm: tpmt_public.nameAlg.try_into()?,
                auth_policy: tpmt_public.authPolicy.try_into()?,
                parameters: unsafe { tpmt_public.parameters.eccDetail }.try_into()?,
                unique: unsafe { tpmt_public.unique.ecc }.try_into()?,
            }),
            PublicAlgorithm::SymCipher => Ok(Public::SymCipher {
                object_attributes: tpmt_public.objectAttributes.into(),
                name_hashing_algorithm: tpmt_public.nameAlg.try_into()?,
                auth_policy: tpmt_public.authPolicy.try_into()?,
                parameters: unsafe { tpmt_public.parameters.symDetail }.try_into()?,
                unique: unsafe { tpmt_public.unique.sym }.try_into()?,
            }),
        }
    }
}

impl Marshall for Public {
    const BUFFER_SIZE: usize = size_of::<TPMT_PUBLIC>();

    /// Produce a marshalled [TPMT_PUBLIC]
    ///
    /// Note: for [TPM2B_PUBLIC] marshalling use [PublicBuffer][`crate::structures::PublicBuffer]
    fn marshall(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; Self::BUFFER_SIZE];
        let mut offset = 0;

        let ret = Error::from_tss_rc(unsafe {
            crate::tss2_esys::Tss2_MU_TPMT_PUBLIC_Marshal(
                &self.clone().into(),
                buffer.as_mut_ptr(),
                Self::BUFFER_SIZE.try_into().map_err(|e| {
                    error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?,
                &mut offset,
            )
        });

        if !ret.is_success() {
            return Err(ret);
        }

        let checked_offset = usize::try_from(offset).map_err(|e| {
            error!("Failed to parse offset as usize: {}", e);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        buffer.truncate(checked_offset);

        Ok(buffer)
    }
}

impl UnMarshall for Public {
    /// Unmarshall the structure from [`TPMT_PUBLIC`]
    ///
    /// Note: for [TPM2B_PUBLIC] unmarshalling use [PublicBuffer][`crate::structures::PublicBuffer]
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self> {
        let mut dest = TPMT_PUBLIC::default();
        let mut offset = 0;

        let ret = Error::from_tss_rc(unsafe {
            crate::tss2_esys::Tss2_MU_TPMT_PUBLIC_Unmarshal(
                marshalled_data.as_ptr(),
                marshalled_data.len().try_into().map_err(|e| {
                    error!("Failed to convert length of marshalled data: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?,
                &mut offset,
                &mut dest,
            )
        });

        if !ret.is_success() {
            return Err(ret);
        }

        Public::try_from(dest)
    }
}

impl TryFrom<TPM2B_PUBLIC> for Public {
    type Error = Error;

    fn try_from(tpm2b_public: TPM2B_PUBLIC) -> Result<Self> {
        Public::try_from(tpm2b_public.publicArea)
    }
}

impl TryFrom<Public> for TPM2B_PUBLIC {
    type Error = Error;

    fn try_from(public: Public) -> Result<Self> {
        let mut buffer = vec![0; Public::BUFFER_SIZE];
        let mut size = 0;
        let public_area = TPMT_PUBLIC::from(public);

        let ret = Error::from_tss_rc(unsafe {
            crate::tss2_esys::Tss2_MU_TPMT_PUBLIC_Marshal(
                &public_area,
                buffer.as_mut_ptr(),
                Public::BUFFER_SIZE.try_into().map_err(|e| {
                    error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?,
                &mut size,
            )
        });

        if !ret.is_success() {
            return Err(ret);
        }

        Ok(TPM2B_PUBLIC {
            size: size.try_into().map_err(|e| {
                error!(
                    "Failed to convert size of buffer from TSS size_t type: {}",
                    e
                );
                Error::local_error(WrapperErrorKind::InvalidParam)
            })?,
            publicArea: public_area,
        })
    }
}
