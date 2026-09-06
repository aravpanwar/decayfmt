// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    tss2_esys::{TPM2_KEY_BITS, TPMI_AES_KEY_BITS, TPMI_RSA_KEY_BITS, TPMI_SM4_KEY_BITS},
    Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
/// AES key bits interface type
///
/// # Details
/// This corresponds to TPMI_AES_KEY_BITS
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum AesKeyBits {
    Aes128,
    Aes192,
    Aes256,
}

impl From<AesKeyBits> for TPMI_AES_KEY_BITS {
    fn from(aes_key_bits: AesKeyBits) -> TPMI_AES_KEY_BITS {
        match aes_key_bits {
            AesKeyBits::Aes128 => 128,
            AesKeyBits::Aes192 => 192,
            AesKeyBits::Aes256 => 256,
        }
    }
}

impl TryFrom<TPMI_AES_KEY_BITS> for AesKeyBits {
    type Error = Error;
    fn try_from(tpmi_aes_key_bits: TPMI_AES_KEY_BITS) -> Result<AesKeyBits> {
        match tpmi_aes_key_bits {
            128 => Ok(AesKeyBits::Aes128),
            192 => Ok(AesKeyBits::Aes192),
            256 => Ok(AesKeyBits::Aes256),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

/// SM4 key bits interface type
///
/// # Details
/// This corresponds to TPMI_SM4_KEY_BITS
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Sm4KeyBits {
    Sm4_128,
}

impl From<Sm4KeyBits> for TPMI_SM4_KEY_BITS {
    fn from(sm4_key_bits: Sm4KeyBits) -> TPMI_SM4_KEY_BITS {
        match sm4_key_bits {
            Sm4KeyBits::Sm4_128 => 128,
        }
    }
}

impl TryFrom<TPMI_SM4_KEY_BITS> for Sm4KeyBits {
    type Error = Error;
    fn try_from(tpmi_sm4_key_bits: TPMI_SM4_KEY_BITS) -> Result<Sm4KeyBits> {
        match tpmi_sm4_key_bits {
            128 => Ok(Sm4KeyBits::Sm4_128),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

/// Camellia key bits interface type
///
/// # Details
/// This corresponds to TPMI_CAMELLIA_KEY_BITS
// This should convert to and from TPMI_CAMELLIA_KEY_BITS
// but in version 2.3.X version of tpm2-tss
// lib this type had the wrong name so instead
// it converts to and from TPM2_KEY_BITS.
// This is an acceptable compromise because
// the interface type defined as
// pub type TPMI_CAMELLIA_KEY_BITS = TPM2_KEY_BITS
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum CamelliaKeyBits {
    Camellia128,
    Camellia192,
    Camellia256,
}

impl From<CamelliaKeyBits> for TPM2_KEY_BITS {
    fn from(camellia_key_bits: CamelliaKeyBits) -> TPM2_KEY_BITS {
        match camellia_key_bits {
            CamelliaKeyBits::Camellia128 => 128,
            CamelliaKeyBits::Camellia192 => 192,
            CamelliaKeyBits::Camellia256 => 256,
        }
    }
}

impl TryFrom<TPM2_KEY_BITS> for CamelliaKeyBits {
    type Error = Error;
    fn try_from(tpmi_camellia_key_bits: TPM2_KEY_BITS) -> Result<CamelliaKeyBits> {
        match tpmi_camellia_key_bits {
            128 => Ok(CamelliaKeyBits::Camellia128),
            192 => Ok(CamelliaKeyBits::Camellia192),
            256 => Ok(CamelliaKeyBits::Camellia256),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

/// RSA key bits interface type
///
/// # Details
/// This corresponds to TPMI_RSA_KEY_BITS
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum RsaKeyBits {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl From<RsaKeyBits> for TPMI_RSA_KEY_BITS {
    fn from(rsa_key_bits: RsaKeyBits) -> TPMI_RSA_KEY_BITS {
        match rsa_key_bits {
            RsaKeyBits::Rsa1024 => 1024,
            RsaKeyBits::Rsa2048 => 2048,
            RsaKeyBits::Rsa3072 => 3072,
            RsaKeyBits::Rsa4096 => 4096,
        }
    }
}

impl TryFrom<TPMI_RSA_KEY_BITS> for RsaKeyBits {
    type Error = Error;

    fn try_from(tpmi_rsa_key_bits: TPMI_RSA_KEY_BITS) -> Result<RsaKeyBits> {
        match tpmi_rsa_key_bits {
            1024 => Ok(RsaKeyBits::Rsa1024),
            2048 => Ok(RsaKeyBits::Rsa2048),
            3072 => Ok(RsaKeyBits::Rsa3072),
            4096 => Ok(RsaKeyBits::Rsa4096),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
