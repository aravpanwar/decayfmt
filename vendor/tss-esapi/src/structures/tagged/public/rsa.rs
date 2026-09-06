// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::{algorithm::RsaSchemeAlgorithm, key_bits::RsaKeyBits},
    structures::{RsaScheme, SymmetricDefinitionObject},
    tss2_esys::{TPMS_RSA_PARMS, UINT32},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};

/// Builder for `TPMS_RSA_PARMS` values.
#[derive(Copy, Clone, Default, Debug)]
pub struct PublicRsaParametersBuilder {
    symmetric: Option<SymmetricDefinitionObject>,
    rsa_scheme: Option<RsaScheme>,
    key_bits: Option<RsaKeyBits>,
    exponent: Option<RsaExponent>,
    is_signing_key: bool,
    is_decryption_key: bool,
    restricted: bool,
}

impl PublicRsaParametersBuilder {
    /// Creates a new [PublicRsaParametersBuilder]
    pub const fn new() -> Self {
        PublicRsaParametersBuilder {
            symmetric: None,
            rsa_scheme: None,
            key_bits: None,
            exponent: None,
            is_signing_key: false,
            is_decryption_key: false,
            restricted: false,
        }
    }

    /// Creates a [PublicRsaParametersBuilder] that is setup
    /// to build a restricted decryption key.
    pub const fn new_restricted_decryption_key(
        symmetric: SymmetricDefinitionObject,
        key_bits: RsaKeyBits,
        exponent: RsaExponent,
    ) -> Self {
        PublicRsaParametersBuilder {
            symmetric: Some(symmetric),
            rsa_scheme: Some(RsaScheme::Null),
            key_bits: Some(key_bits),
            exponent: Some(exponent),
            is_signing_key: false,
            is_decryption_key: true,
            restricted: true,
        }
    }

    /// Creates a [PublicRsaParametersBuilder] that is setup
    /// to build an unrestricted signing key.
    pub const fn new_unrestricted_signing_key(
        rsa_scheme: RsaScheme,
        key_bits: RsaKeyBits,
        exponent: RsaExponent,
    ) -> Self {
        PublicRsaParametersBuilder {
            symmetric: None,
            rsa_scheme: Some(rsa_scheme),
            key_bits: Some(key_bits),
            exponent: Some(exponent),
            is_signing_key: true,
            is_decryption_key: false,
            restricted: false,
        }
    }

    /// Adds a [SymmetricDefinitionObject] to the [PublicRsaParametersBuilder].
    pub const fn with_symmetric(mut self, symmetric: SymmetricDefinitionObject) -> Self {
        self.symmetric = Some(symmetric);
        self
    }

    /// Adds a [RsaScheme] to the [PublicRsaParametersBuilder].
    pub const fn with_scheme(mut self, rsa_scheme: RsaScheme) -> Self {
        self.rsa_scheme = Some(rsa_scheme);
        self
    }

    /// Adds [RsaKeyBits] to the [PublicRsaParametersBuilder].
    pub const fn with_key_bits(mut self, key_bits: RsaKeyBits) -> Self {
        self.key_bits = Some(key_bits);
        self
    }

    /// Adds [RsaExponent] to the [PublicRsaParametersBuilder].
    pub const fn with_exponent(mut self, exponent: RsaExponent) -> Self {
        self.exponent = Some(exponent);
        self
    }

    /// Adds a flag that indicates if the key is going to be used
    /// for signing to the [PublicRsaParametersBuilder].
    ///
    /// # Arguments
    /// * `set` - `true` inidcates that the key is going to be used for signing operations.
    ///   `false` indicates that the key is not going to be used for signing operations.
    pub const fn with_is_signing_key(mut self, set: bool) -> Self {
        self.is_signing_key = set;
        self
    }

    /// Adds a flag that indicates if the key is going to be used for
    /// decryption to the [PublicRsaParametersBuilder].
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the key is going to be used for decryption operations.
    ///   `false` indicates that the key is not going to be used for decryption operations.
    pub const fn with_is_decryption_key(mut self, set: bool) -> Self {
        self.is_decryption_key = set;
        self
    }

    /// Adds a flag that inidcates if the key is going to be restrictied to
    /// the [PublicRsaParametersBuilder].
    ///
    /// # Arguments
    /// * `set` - `true` indicates that it is going to be a restricted key.
    ///   `false` indicates that it is going to be a non restricted key.
    pub const fn with_restricted(mut self, set: bool) -> Self {
        self.restricted = set;
        self
    }

    /// Build an object given the previously provided parameters.
    ///
    /// The only mandatory parameter is the asymmetric scheme.
    ///
    /// # Errors
    /// * if no asymmetric scheme is set, `ParamsMissing` wrapper error is returned.
    /// * if the `for_signing`, `for_decryption` and `restricted` parameters are
    ///   inconsistent with the rest of the parameters, `InconsistentParams` wrapper
    ///   error is returned
    pub fn build(self) -> Result<PublicRsaParameters> {
        let rsa_scheme = self.rsa_scheme.ok_or_else(|| {
            error!("Scheme parameter is required and has not been set in the PublicRsaParametersBuilder");
            Error::local_error(WrapperErrorKind::ParamsMissing)
        })?;

        let key_bits = self.key_bits.ok_or_else(|| {
            error!("Key bits parameter is required and has not been set in the PublicRsaParametersBuilder");
            Error::local_error(WrapperErrorKind::ParamsMissing)
        })?;

        if self.restricted && self.is_decryption_key {
            if let Some(symmetric) = self.symmetric {
                if symmetric.is_null() {
                    error!("Found symmetric parameter but it was Null but 'restricted' and 'is_decrypt_key' are set to true");
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
            } else {
                error!("Found symmetric parameter, expected it to be Null nor not set at all because 'restricted' and 'is_decrypt_key' are set to false");
                return Err(Error::local_error(WrapperErrorKind::ParamsMissing));
            }
        } else if let Some(symmetric) = self.symmetric {
            if !symmetric.is_null() {
                error!("Found symmetric parameter, expected it to be Null nor not set at all because 'restricted' and 'is_decrypt_key' are set to false");
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
        }

        // TODO: Figure out if it actually should be allowed to not provide
        // these parameters.
        let symmetric_definition_object = self.symmetric.unwrap_or(SymmetricDefinitionObject::Null);
        let exponent = self.exponent.unwrap_or_default();

        if self.restricted {
            if self.is_signing_key
                && rsa_scheme.algorithm() != RsaSchemeAlgorithm::RsaPss
                && rsa_scheme.algorithm() != RsaSchemeAlgorithm::RsaSsa
            {
                error!("Invalid rsa scheme algorithm provided with 'restricted' and 'is_signing_key' set to true");
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }

            if self.is_decryption_key && rsa_scheme.algorithm() != RsaSchemeAlgorithm::Null {
                error!("Invalid rsa scheme algorithm provided with 'restricted' and 'is_decryption_key' set to true");
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
        } else {
            if self.is_decryption_key
                && self.is_signing_key
                && rsa_scheme.algorithm() != RsaSchemeAlgorithm::Null
            {
                error!("Invalid rsa scheme algorithm provided with 'restricted' set to false and 'is_decryption_key' and 'is_signing_key' set to true");
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
            if self.is_signing_key
                && rsa_scheme.algorithm() != RsaSchemeAlgorithm::RsaPss
                && rsa_scheme.algorithm() != RsaSchemeAlgorithm::RsaSsa
                && rsa_scheme.algorithm() != RsaSchemeAlgorithm::Null
            {
                error!("Invalid rsa scheme algorithm provided with 'restricted' set to false and 'is_signing_key' set to true");
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }

            if self.is_decryption_key
                && rsa_scheme.algorithm() != RsaSchemeAlgorithm::RsaEs
                && rsa_scheme.algorithm() != RsaSchemeAlgorithm::Oaep
                && rsa_scheme.algorithm() != RsaSchemeAlgorithm::Null
            {
                error!("Invalid rsa scheme algorithm provided with 'restricted' set to false and 'is_decryption_key' set to true");
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
        }

        Ok(PublicRsaParameters {
            symmetric_definition_object,
            rsa_scheme,
            key_bits,
            exponent,
        })
    }
}

/// Structure used to hold the value of a RSA exponent
#[derive(Default, Clone, Debug, Copy, PartialEq, Eq)]
pub struct RsaExponent {
    value: u32,
}

impl RsaExponent {
    /// Empty exponent (internal value is 0), which is treated by TPMs
    /// as a shorthand for the default value (2^16 + 1).
    pub const ZERO_EXPONENT: Self = RsaExponent { value: 0 };

    /// Function for creating a new RsaExponent
    ///
    /// # Warning
    /// Will not check whether the value is a valid exponent for RSA.
    ///
    /// # Errors
    /// Will return an error if the value passed into the function
    /// is not a valid RSA exponent.
    pub fn create(value: u32) -> Result<Self> {
        Ok(RsaExponent { value })
    }

    /// Method that returns the value of the rsa exponent.
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// No-op. Does not check whether the value is a valid exponent for RSA.
    #[deprecated(
        since = "7.0.1",
        note = "TPMs are only mandated to support 0 as an exponent, with support for and checking of other values being done differently by each manufacturer. See discussion here: https://github.com/parallaxsecond/rust-tss-esapi/pull/332"
    )]
    pub fn is_valid(_: u32) -> bool {
        true
    }
}

impl From<RsaExponent> for UINT32 {
    fn from(rsa_exponent: RsaExponent) -> Self {
        rsa_exponent.value
    }
}

impl TryFrom<UINT32> for RsaExponent {
    type Error = Error;

    fn try_from(tpm_uint32_value: UINT32) -> Result<Self> {
        Ok(RsaExponent {
            value: tpm_uint32_value,
        })
    }
}

/// Structure holding the RSA specific parameters.
///
/// # Details
/// This corresponds to TPMS_RSA_PARMS
///
/// These rsa parameters are specific to the [`crate::structures::Public`] type.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct PublicRsaParameters {
    symmetric_definition_object: SymmetricDefinitionObject,
    rsa_scheme: RsaScheme,
    key_bits: RsaKeyBits,
    exponent: RsaExponent,
}

impl PublicRsaParameters {
    /// Function for creating new [PublicRsaParameters] structure
    pub const fn new(
        symmetric_definition_object: SymmetricDefinitionObject,
        rsa_scheme: RsaScheme,
        key_bits: RsaKeyBits,
        exponent: RsaExponent,
    ) -> Self {
        PublicRsaParameters {
            symmetric_definition_object,
            rsa_scheme,
            key_bits,
            exponent,
        }
    }

    /// Returns the [SymmetricDefinitionObject].
    pub const fn symmetric_definition_object(&self) -> SymmetricDefinitionObject {
        self.symmetric_definition_object
    }

    /// Returns the [RsaScheme]
    pub const fn rsa_scheme(&self) -> RsaScheme {
        self.rsa_scheme
    }

    /// Returns the [RsaKeyBits]
    pub const fn key_bits(&self) -> RsaKeyBits {
        self.key_bits
    }

    /// Returns the exponent in the form of a [RsaExponent]
    pub const fn exponent(&self) -> RsaExponent {
        self.exponent
    }

    /// Get a builder for this structure
    pub const fn builder() -> PublicRsaParametersBuilder {
        PublicRsaParametersBuilder::new()
    }
}

impl From<PublicRsaParameters> for TPMS_RSA_PARMS {
    fn from(public_rsa_parameters: PublicRsaParameters) -> Self {
        TPMS_RSA_PARMS {
            symmetric: public_rsa_parameters.symmetric_definition_object.into(),
            scheme: public_rsa_parameters.rsa_scheme.into(),
            keyBits: public_rsa_parameters.key_bits.into(),
            exponent: public_rsa_parameters.exponent.into(),
        }
    }
}

impl TryFrom<TPMS_RSA_PARMS> for PublicRsaParameters {
    type Error = Error;

    fn try_from(tpms_rsa_parms: TPMS_RSA_PARMS) -> Result<Self> {
        Ok(PublicRsaParameters {
            symmetric_definition_object: tpms_rsa_parms.symmetric.try_into()?,
            rsa_scheme: tpms_rsa_parms.scheme.try_into()?,
            key_bits: tpms_rsa_parms.keyBits.try_into()?,
            exponent: tpms_rsa_parms.exponent.try_into()?,
        })
    }
}
