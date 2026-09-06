// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::constants::tss::{
    TPM2_ST_ATTEST_CERTIFY, TPM2_ST_ATTEST_COMMAND_AUDIT, TPM2_ST_ATTEST_CREATION,
    TPM2_ST_ATTEST_NV, TPM2_ST_ATTEST_NV_DIGEST, TPM2_ST_ATTEST_QUOTE,
    TPM2_ST_ATTEST_SESSION_AUDIT, TPM2_ST_ATTEST_TIME, TPM2_ST_AUTH_SECRET, TPM2_ST_AUTH_SIGNED,
    TPM2_ST_CREATION, TPM2_ST_FU_MANIFEST, TPM2_ST_HASHCHECK, TPM2_ST_NO_SESSIONS, TPM2_ST_NULL,
    TPM2_ST_RSP_COMMAND, TPM2_ST_SESSIONS, TPM2_ST_VERIFIED,
};
use crate::{tss2_esys::TPM2_ST, Error, Result, WrapperErrorKind};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

/// This enum represents the TPM_ST (Structure Tags)
#[derive(FromPrimitive, ToPrimitive, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StructureTag {
    RspCommand = TPM2_ST_RSP_COMMAND,
    Null = TPM2_ST_NULL,
    NoSessions = TPM2_ST_NO_SESSIONS,
    Sessions = TPM2_ST_SESSIONS,
    // Reserved1 = TPM2_ST_RESERVED1,
    // Reserved2 = TPM2_ST_RESERVED2,
    AttestNv = TPM2_ST_ATTEST_NV,
    AttestCommandAudit = TPM2_ST_ATTEST_COMMAND_AUDIT,
    AttestSessionAudit = TPM2_ST_ATTEST_SESSION_AUDIT,
    AttestCertify = TPM2_ST_ATTEST_CERTIFY,
    AttestQuote = TPM2_ST_ATTEST_QUOTE,
    AttestTime = TPM2_ST_ATTEST_TIME,
    AttestCreation = TPM2_ST_ATTEST_CREATION,
    // Reserved3 = TPM2_ST_RESERVED3,
    AttestNvDigest = TPM2_ST_ATTEST_NV_DIGEST,
    Creation = TPM2_ST_CREATION,
    Verified = TPM2_ST_VERIFIED,
    AuthSecret = TPM2_ST_AUTH_SECRET,
    Hashcheck = TPM2_ST_HASHCHECK,
    AuthSigned = TPM2_ST_AUTH_SIGNED,
    FuManifest = TPM2_ST_FU_MANIFEST,
}

impl TryFrom<TPM2_ST> for StructureTag {
    type Error = Error;
    fn try_from(tpm_structure_tag: TPM2_ST) -> Result<Self> {
        StructureTag::from_u16(tpm_structure_tag).ok_or_else(|| {
            error!(
                "value = {} did not match any StructureTag.",
                tpm_structure_tag
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

impl From<StructureTag> for TPM2_ST {
    fn from(structure_tag: StructureTag) -> Self {
        // The values are well defined so this cannot fail.
        structure_tag.to_u16().unwrap()
    }
}
