// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::tss::TPM2_GENERATED_VALUE,
    interface_types::structure_tags::AttestationType,
    structures::{AttestInfo, ClockInfo, Data, Name},
    traits::{Marshall, UnMarshall},
    tss2_esys::TPMS_ATTEST,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
};

/// Type for holding attestation data
///
/// # Details
/// Corresponds to `TPMS_ATTEST`.
#[derive(Debug, Clone)]
pub struct Attest {
    attestation_type: AttestationType,
    qualified_signer: Name,
    extra_data: Data,
    clock_info: ClockInfo,
    firmware_version: u64,
    attested: AttestInfo,
}

impl Attest {
    /// Returns attestation type
    pub const fn attestation_type(&self) -> AttestationType {
        self.attestation_type
    }

    /// Returns the qualified name of the signing object.
    pub const fn qualified_signer(&self) -> &Name {
        &self.qualified_signer
    }

    /// Returns the extra data specified by the caller.
    pub const fn extra_data(&self) -> &Data {
        &self.extra_data
    }

    /// Returns the internal TPM clock data.
    pub const fn clock_info(&self) -> &ClockInfo {
        &self.clock_info
    }

    /// Returns TPM firmware version number.
    pub const fn firmware_version(&self) -> u64 {
        self.firmware_version
    }

    /// Returns types specific attestation information
    pub const fn attested(&self) -> &AttestInfo {
        &self.attested
    }
}

impl From<Attest> for TPMS_ATTEST {
    fn from(attest: Attest) -> Self {
        TPMS_ATTEST {
            magic: TPM2_GENERATED_VALUE,
            type_: attest.attestation_type.into(),
            qualifiedSigner: attest.qualified_signer.into(),
            extraData: attest.extra_data.into(),
            clockInfo: attest.clock_info.into(),
            firmwareVersion: attest.firmware_version,
            attested: attest.attested.into(),
        }
    }
}

impl TryFrom<TPMS_ATTEST> for Attest {
    type Error = Error;

    fn try_from(tpms_attest: TPMS_ATTEST) -> Result<Self> {
        if tpms_attest.magic != TPM2_GENERATED_VALUE {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        let attestation_type = AttestationType::try_from(tpms_attest.type_)?;
        Ok(Attest {
            attestation_type,
            qualified_signer: Name::try_from(tpms_attest.qualifiedSigner)?,
            extra_data: Data::try_from(tpms_attest.extraData)?,
            clock_info: ClockInfo::try_from(tpms_attest.clockInfo)?,
            firmware_version: tpms_attest.firmwareVersion,
            attested: match attestation_type {
                AttestationType::Certify => AttestInfo::Certify {
                    info: unsafe { tpms_attest.attested.certify }.try_into()?,
                },
                AttestationType::Quote => AttestInfo::Quote {
                    info: unsafe { tpms_attest.attested.quote }.try_into()?,
                },
                AttestationType::SessionAudit => AttestInfo::SessionAudit {
                    info: unsafe { tpms_attest.attested.sessionAudit }.try_into()?,
                },
                AttestationType::CommandAudit => AttestInfo::CommandAudit {
                    info: unsafe { tpms_attest.attested.commandAudit }.try_into()?,
                },
                AttestationType::Time => AttestInfo::Time {
                    info: unsafe { tpms_attest.attested.time }.try_into()?,
                },
                AttestationType::Creation => AttestInfo::Creation {
                    info: unsafe { tpms_attest.attested.creation }.try_into()?,
                },
                AttestationType::Nv => AttestInfo::Nv {
                    info: unsafe { tpms_attest.attested.nv }.try_into()?,
                },
                AttestationType::NvDigest => {
                    error!("NvDigest attestation type is currently not supported");
                    return Err(Error::local_error(WrapperErrorKind::UnsupportedParam));
                }
            },
        })
    }
}

impl Marshall for Attest {
    const BUFFER_SIZE: usize = size_of::<TPMS_ATTEST>();

    /// Produce a marshalled [`TPMS_ATTEST`]
    fn marshall(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; Self::BUFFER_SIZE];
        let mut offset = 0;

        let ret = Error::from_tss_rc(unsafe {
            crate::tss2_esys::Tss2_MU_TPMS_ATTEST_Marshal(
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

impl UnMarshall for Attest {
    /// Unmarshall the structure from [`TPMS_ATTEST`]
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self> {
        let mut dest = TPMS_ATTEST::default();
        let mut offset = 0;

        let ret = Error::from_tss_rc(unsafe {
            crate::tss2_esys::Tss2_MU_TPMS_ATTEST_Unmarshal(
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

        Attest::try_from(dest)
    }
}
