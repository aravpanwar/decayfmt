// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

pub mod ak;
pub mod cipher;
pub mod ek;
pub mod nv;
pub mod pcr;
pub mod public;
pub mod transient;

use std::convert::TryFrom;

use crate::{
    attributes::ObjectAttributesBuilder,
    interface_types::{algorithm::AsymmetricAlgorithm, ecc::EccCurve, key_bits::RsaKeyBits},
    structures::PublicBuilder,
    Error, WrapperErrorKind,
};

/// KeyCustomization allows to adjust how a key is going to be created
pub trait KeyCustomization {
    /// Alter the attributes used on key creation
    fn attributes(&self, attributes_builder: ObjectAttributesBuilder) -> ObjectAttributesBuilder {
        attributes_builder
    }

    /// Alter the key template used on key creation
    fn template(&self, template_builder: PublicBuilder) -> PublicBuilder {
        template_builder
    }
}

/// IntoKeyCustomization transforms a type into a type that support KeyCustomization
pub trait IntoKeyCustomization {
    type T: KeyCustomization;

    fn into_key_customization(self) -> Option<Self::T>;
}

impl<T: KeyCustomization> IntoKeyCustomization for T {
    type T = T;

    fn into_key_customization(self) -> Option<Self::T> {
        Some(self)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct DefaultKey;
#[derive(Debug, Copy, Clone)]
pub struct DefaultKeyImpl;
impl KeyCustomization for DefaultKeyImpl {}

impl IntoKeyCustomization for DefaultKey {
    type T = DefaultKeyImpl;

    fn into_key_customization(self) -> Option<Self::T> {
        None
    }
}

impl IntoKeyCustomization for Option<DefaultKey> {
    type T = DefaultKeyImpl;

    fn into_key_customization(self) -> Option<Self::T> {
        None
    }
}

/// Enum representing the asymmetric algorithm interface type with specific properties.
///
/// # Details
/// Use this instead of [AsymmetricAlgorithm].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AsymmetricAlgorithmSelection {
    Rsa(RsaKeyBits),
    Ecc(EccCurve),
}

/// The conversion assumes for RSA 2048 bit size and for ECC the Nist P256 curve,
/// which matches the defaults in tpm2-tools.
impl TryFrom<AsymmetricAlgorithm> for AsymmetricAlgorithmSelection {
    type Error = Error;

    fn try_from(value: AsymmetricAlgorithm) -> Result<Self, Self::Error> {
        match value {
            AsymmetricAlgorithm::Rsa => Ok(AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048)),
            AsymmetricAlgorithm::Ecc => Ok(AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256)),
            AsymmetricAlgorithm::Null => {
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
        }
    }
}
