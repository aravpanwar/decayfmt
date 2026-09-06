// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::{algorithm::EccSchemeAlgorithm, ecc::EccCurve},
    structures::{EccScheme, KeyDerivationFunctionScheme, SymmetricDefinitionObject},
    tss2_esys::TPMS_ECC_PARMS,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};

/// Builder for PublicEccParameters.
#[derive(Copy, Clone, Debug, Default)]
pub struct PublicEccParametersBuilder {
    symmetric: Option<SymmetricDefinitionObject>,
    ecc_scheme: Option<EccScheme>,
    ecc_curve: Option<EccCurve>,
    key_derivation_function_scheme: Option<KeyDerivationFunctionScheme>,
    is_signing_key: bool,
    is_decryption_key: bool,
    restricted: bool,
}

impl PublicEccParametersBuilder {
    pub const fn new() -> Self {
        PublicEccParametersBuilder {
            symmetric: None,
            ecc_scheme: None,
            ecc_curve: None,
            key_derivation_function_scheme: None,
            is_signing_key: false,
            is_decryption_key: false,
            restricted: false,
        }
    }

    /// Create parameters for a restricted decryption key (i.e. a storage key)
    pub const fn new_restricted_decryption_key(
        symmetric: SymmetricDefinitionObject,
        curve: EccCurve,
    ) -> Self {
        PublicEccParametersBuilder {
            symmetric: Some(symmetric),
            ecc_scheme: Some(EccScheme::Null),
            ecc_curve: Some(curve),
            key_derivation_function_scheme: Some(KeyDerivationFunctionScheme::Null),
            is_signing_key: false,
            is_decryption_key: true,
            restricted: true,
        }
    }

    /// Create parameters for an unrestricted signing key
    pub const fn new_unrestricted_signing_key(scheme: EccScheme, curve: EccCurve) -> Self {
        PublicEccParametersBuilder {
            symmetric: None,
            ecc_scheme: Some(scheme),
            ecc_curve: Some(curve),
            key_derivation_function_scheme: Some(KeyDerivationFunctionScheme::Null),
            is_signing_key: true,
            is_decryption_key: false,
            restricted: false,
        }
    }

    /// Adds a [SymmetricDefinitionObject] to the [PublicEccParametersBuilder].
    pub const fn with_symmetric(mut self, symmetric: SymmetricDefinitionObject) -> Self {
        self.symmetric = Some(symmetric);
        self
    }

    /// Adds a [EccScheme] to the [PublicEccParametersBuilder].
    pub const fn with_ecc_scheme(mut self, ecc_scheme: EccScheme) -> Self {
        self.ecc_scheme = Some(ecc_scheme);
        self
    }

    /// Adds [EccCurve] to the [PublicEccParametersBuilder].
    pub const fn with_curve(mut self, ecc_curve: EccCurve) -> Self {
        self.ecc_curve = Some(ecc_curve);
        self
    }

    /// Adds [KeyDerivationFunctionScheme] to the [PublicEccParametersBuilder].
    pub const fn with_key_derivation_function_scheme(
        mut self,
        key_derivation_function_scheme: KeyDerivationFunctionScheme,
    ) -> Self {
        self.key_derivation_function_scheme = Some(key_derivation_function_scheme);
        self
    }

    /// Adds a flag that indicates if the key is going to be used
    /// for signing to the [PublicEccParametersBuilder].
    ///
    /// # Arguments
    /// * `set` - `true` inidcates that the key is going to be used for signing operations.
    ///   `false` indicates that the key is not going to be used for signing operations.
    pub const fn with_is_signing_key(mut self, set: bool) -> Self {
        self.is_signing_key = set;
        self
    }

    /// Adds a flag that indicates if the key is going to be used for
    /// decryption to the [PublicEccParametersBuilder].
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the key is going to be used for decryption operations.
    ///   `false` indicates that the key is not going to be used for decryption operations.
    pub const fn with_is_decryption_key(mut self, set: bool) -> Self {
        self.is_decryption_key = set;
        self
    }

    /// Adds a flag that inidcates if the key is going to be restrictied to
    /// the [PublicEccParametersBuilder].
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
    /// The only mandatory parameters are the asymmetric scheme and the elliptic curve.
    ///
    /// # Errors
    /// * if no asymmetric scheme is set, `ParamsMissing` wrapper error is returned.
    /// * if the `for_signing`, `for_decryption` and `restricted` parameters are
    ///   inconsistent with the rest of the parameters, `InconsistentParams` wrapper
    ///   error is returned
    pub fn build(self) -> Result<PublicEccParameters> {
        let ecc_scheme = self.ecc_scheme.ok_or_else(|| {
            error!("Scheme is required nad has not been set in the PublicEccParametersBuilder");
            Error::local_error(WrapperErrorKind::ParamsMissing)
        })?;

        let ecc_curve = self.ecc_curve.ok_or_else(|| {
            error!("Curve is required nad has not been set in the PublicEccParametersBuilder");
            Error::local_error(WrapperErrorKind::ParamsMissing)
        })?;

        let key_derivation_function_scheme = self.key_derivation_function_scheme.ok_or_else(|| {
            error!("Key derivation function scheme is required nad has not been set in the PublicEccParametersBuilder");
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

        if self.is_decryption_key && self.is_signing_key {
            error!("Key cannot be decryption and signing key at the same time");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        // TODO: Figure out if it actually should be allowed to not provide
        // these parameters.
        let symmetric_definition_object = self.symmetric.unwrap_or(SymmetricDefinitionObject::Null);

        if self.is_signing_key
            && ecc_scheme.algorithm() != EccSchemeAlgorithm::EcDsa
            && ecc_scheme.algorithm() != EccSchemeAlgorithm::EcDaa
            && ecc_scheme.algorithm() != EccSchemeAlgorithm::Sm2
            && ecc_scheme.algorithm() != EccSchemeAlgorithm::EcSchnorr
        {
            error!("Signing key can use only EcDsa, EcDaa, Sm2 or EcSchorr schemes");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        if self.is_decryption_key
            && ecc_scheme.algorithm() != EccSchemeAlgorithm::Sm2
            && ecc_scheme.algorithm() != EccSchemeAlgorithm::EcDh
            && ecc_scheme.algorithm() != EccSchemeAlgorithm::EcMqv
            && ecc_scheme.algorithm() != EccSchemeAlgorithm::Null
        {
            error!("Decryption key can use only Sm2, EcDh, EcMqv and Null schemes");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        match (ecc_curve, ecc_scheme.algorithm()) {
            (EccCurve::BnP256 | EccCurve::BnP638, EccSchemeAlgorithm::EcDaa)
            | (EccCurve::Sm2P256, EccSchemeAlgorithm::Sm2)
            | (
                EccCurve::NistP192
                | EccCurve::NistP224
                | EccCurve::NistP256
                | EccCurve::NistP384
                | EccCurve::NistP521,
                EccSchemeAlgorithm::EcDh
                | EccSchemeAlgorithm::EcDaa
                | EccSchemeAlgorithm::EcDsa
                | EccSchemeAlgorithm::EcMqv
                | EccSchemeAlgorithm::EcSchnorr,
            )
            | (_, EccSchemeAlgorithm::Null) => (),

            _ => {
                error!(
                    "Mismatch between elliptic curve ({:#?}) and signing scheme ({:#?}) used",
                    ecc_curve,
                    ecc_scheme.algorithm()
                );
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
        }

        Ok(PublicEccParameters {
            symmetric_definition_object,
            ecc_scheme,
            ecc_curve,
            key_derivation_function_scheme,
        })
    }
}

/// Structure holding the ECC specific parameters.
///
/// # Details
/// This corresponds to TPMS_ECC_PARMS.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct PublicEccParameters {
    symmetric_definition_object: SymmetricDefinitionObject,
    ecc_scheme: EccScheme,
    ecc_curve: EccCurve,
    key_derivation_function_scheme: KeyDerivationFunctionScheme,
}

impl PublicEccParameters {
    /// Creates new EccParameters structure
    pub const fn new(
        symmetric_definition_object: SymmetricDefinitionObject,
        ecc_scheme: EccScheme,
        ecc_curve: EccCurve,
        key_derivation_function_scheme: KeyDerivationFunctionScheme,
    ) -> PublicEccParameters {
        PublicEccParameters {
            symmetric_definition_object,
            ecc_scheme,
            ecc_curve,
            key_derivation_function_scheme,
        }
    }

    /// Returns the [SymmetricDefinitionObject].
    pub const fn symmetric_definition_object(&self) -> SymmetricDefinitionObject {
        self.symmetric_definition_object
    }

    /// Returns the [EccScheme]
    pub const fn ecc_scheme(&self) -> EccScheme {
        self.ecc_scheme
    }

    /// Returns the [EccCurve]
    pub const fn ecc_curve(&self) -> EccCurve {
        self.ecc_curve
    }

    /// Returns the [KeyDerivationFunctionScheme]
    pub const fn key_derivation_function_scheme(&self) -> KeyDerivationFunctionScheme {
        self.key_derivation_function_scheme
    }

    /// Get a builder for this structure
    pub const fn builder() -> PublicEccParametersBuilder {
        PublicEccParametersBuilder::new()
    }
}

impl From<PublicEccParameters> for TPMS_ECC_PARMS {
    fn from(public_ecc_parameters: PublicEccParameters) -> Self {
        TPMS_ECC_PARMS {
            symmetric: public_ecc_parameters.symmetric_definition_object.into(),
            scheme: public_ecc_parameters.ecc_scheme.into(),
            curveID: public_ecc_parameters.ecc_curve.into(),
            kdf: public_ecc_parameters.key_derivation_function_scheme.into(),
        }
    }
}

impl TryFrom<TPMS_ECC_PARMS> for PublicEccParameters {
    type Error = Error;

    fn try_from(tpms_ecc_parms: TPMS_ECC_PARMS) -> Result<PublicEccParameters> {
        Ok(PublicEccParameters {
            symmetric_definition_object: tpms_ecc_parms.symmetric.try_into()?,
            ecc_scheme: tpms_ecc_parms.scheme.try_into()?,
            ecc_curve: tpms_ecc_parms.curveID.try_into()?,
            key_derivation_function_scheme: tpms_ecc_parms.kdf.try_into()?,
        })
    }
}
