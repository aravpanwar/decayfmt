// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{structures::KeyedHashScheme, tss2_esys::TPMS_KEYEDHASH_PARMS, Error, Result};
use std::convert::{TryFrom, TryInto};

/// Keyed hash parameters
///
/// # Details
/// Corresponds to TPMS_KEYEDHASH_PARMS
///
/// These keyed hash parameters are specific to the [`crate::structures::Public`] type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeyedHashParameters {
    keyed_hash_scheme: KeyedHashScheme,
}

impl PublicKeyedHashParameters {
    pub const fn new(keyed_hash_scheme: KeyedHashScheme) -> PublicKeyedHashParameters {
        PublicKeyedHashParameters { keyed_hash_scheme }
    }
}

impl TryFrom<TPMS_KEYEDHASH_PARMS> for PublicKeyedHashParameters {
    type Error = Error;

    fn try_from(tpms_keyed_hash_parms: TPMS_KEYEDHASH_PARMS) -> Result<Self> {
        Ok(PublicKeyedHashParameters {
            keyed_hash_scheme: tpms_keyed_hash_parms.scheme.try_into()?,
        })
    }
}

impl From<PublicKeyedHashParameters> for TPMS_KEYEDHASH_PARMS {
    fn from(public_keyed_hash_prams: PublicKeyedHashParameters) -> Self {
        TPMS_KEYEDHASH_PARMS {
            scheme: public_keyed_hash_prams.keyed_hash_scheme.into(),
        }
    }
}
