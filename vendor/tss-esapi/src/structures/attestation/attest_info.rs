// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::{
        CertifyInfo, CommandAuditInfo, CreationInfo, NvCertifyInfo, QuoteInfo, SessionAuditInfo,
        TimeAttestInfo,
    },
    tss2_esys::TPMU_ATTEST,
};

/// Enum that holds the different types of
/// attest info.
///
/// # Details
/// This type does to some degree corresponds to the
/// TPMU_ATTEST but with the TPM_ST_ATTEST selectore
/// included.
#[derive(Debug, Clone)]
pub enum AttestInfo {
    Certify { info: CertifyInfo },
    Quote { info: QuoteInfo },
    SessionAudit { info: SessionAuditInfo },
    CommandAudit { info: CommandAuditInfo },
    Time { info: TimeAttestInfo },
    Creation { info: CreationInfo },
    Nv { info: NvCertifyInfo },
    // NvDigest, the TPMS_NV_DIGEST_CERTIFY_INFO,
    // was first added in the 3.1.0 version of the tpm2-tss
}

impl From<AttestInfo> for TPMU_ATTEST {
    fn from(attest_info: AttestInfo) -> Self {
        match attest_info {
            AttestInfo::Certify { info } => TPMU_ATTEST {
                certify: info.into(),
            },
            AttestInfo::Quote { info } => TPMU_ATTEST { quote: info.into() },
            AttestInfo::SessionAudit { info } => TPMU_ATTEST {
                sessionAudit: info.into(),
            },
            AttestInfo::CommandAudit { info } => TPMU_ATTEST {
                commandAudit: info.into(),
            },
            AttestInfo::Time { info } => TPMU_ATTEST { time: info.into() },
            AttestInfo::Creation { info } => TPMU_ATTEST {
                creation: info.into(),
            },
            AttestInfo::Nv { info } => TPMU_ATTEST { nv: info.into() },
        }
    }
}
