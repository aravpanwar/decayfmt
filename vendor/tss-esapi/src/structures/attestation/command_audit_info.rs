// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::AlgorithmIdentifier, interface_types::algorithm::HashingAlgorithm,
    structures::Digest, tss2_esys::TPMS_COMMAND_AUDIT_INFO, Error, Result,
};

use std::convert::{TryFrom, TryInto};

/// Structure holding the attested data for
/// TPM2_GetCommandAuditDigest().
///
/// # Details
/// This corresponds to the TPMS_COMMAND_AUDIT_INFO
#[derive(Debug, Clone)]
pub struct CommandAuditInfo {
    audit_counter: u64,
    hashing_algorithm: HashingAlgorithm,
    audit_digest: Digest,
    command_digest: Digest,
}

impl CommandAuditInfo {
    /// Returns the audit counter
    pub const fn audit_counter(&self) -> u64 {
        self.audit_counter
    }

    /// Returns the hash algorithm used for the command audit
    pub const fn hashing_algorithm(&self) -> HashingAlgorithm {
        self.hashing_algorithm
    }

    /// Returns the audit digest
    pub const fn audit_digest(&self) -> &Digest {
        &self.audit_digest
    }

    /// Returns the command digest
    pub const fn command_digest(&self) -> &Digest {
        &self.command_digest
    }
}

impl From<CommandAuditInfo> for TPMS_COMMAND_AUDIT_INFO {
    fn from(command_audit_info: CommandAuditInfo) -> Self {
        TPMS_COMMAND_AUDIT_INFO {
            auditCounter: command_audit_info.audit_counter,
            digestAlg: AlgorithmIdentifier::from(command_audit_info.hashing_algorithm).into(),
            auditDigest: command_audit_info.audit_digest.into(),
            commandDigest: command_audit_info.command_digest.into(),
        }
    }
}

impl TryFrom<TPMS_COMMAND_AUDIT_INFO> for CommandAuditInfo {
    type Error = Error;

    fn try_from(tpms_command_audit_info: TPMS_COMMAND_AUDIT_INFO) -> Result<Self> {
        Ok(CommandAuditInfo {
            audit_counter: tpms_command_audit_info.auditCounter,
            hashing_algorithm: AlgorithmIdentifier::try_from(tpms_command_audit_info.digestAlg)?
                .try_into()?,
            audit_digest: tpms_command_audit_info.auditDigest.try_into()?,
            command_digest: tpms_command_audit_info.commandDigest.try_into()?,
        })
    }
}
