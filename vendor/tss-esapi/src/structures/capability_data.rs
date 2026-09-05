// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::CapabilityType,
    structures::{
        AlgorithmPropertyList, CommandCodeAttributesList, CommandCodeList, EccCurveList,
        HandleList, PcrSelectionList, TaggedPcrPropertyList, TaggedTpmPropertyList,
    },
    tss2_esys::{TPM2_CAP, TPM2_MAX_CAP_BUFFER, TPMS_CAPABILITY_DATA, TPMU_CAPABILITIES},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};
use std::mem::size_of;

/// A representation of all the capabilites that can be associated
/// with a TPM.
///
/// # Details
/// This corresponds to `TPMS_CAPABILITY_DATA`
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum CapabilityData {
    Algorithms(AlgorithmPropertyList),
    Handles(HandleList),
    Commands(CommandCodeAttributesList),
    PpCommands(CommandCodeList),
    AuditCommands(CommandCodeList),
    AssignedPcr(PcrSelectionList),
    TpmProperties(TaggedTpmPropertyList),
    PcrProperties(TaggedPcrPropertyList),
    EccCurves(EccCurveList),
    // These are in the TPM TPMU_CAPABILITIES, but are not defined by esapi-2.4.1
    // AuthPolicies(),
    // ActData(),
}

pub const fn max_cap_size<T>() -> usize {
    (TPM2_MAX_CAP_BUFFER as usize - size_of::<TPM2_CAP>() - size_of::<u32>()) / size_of::<T>()
}

impl From<CapabilityData> for TPMS_CAPABILITY_DATA {
    fn from(capability_data: CapabilityData) -> Self {
        match capability_data {
            CapabilityData::Algorithms(data) => TPMS_CAPABILITY_DATA {
                capability: CapabilityType::Algorithms.into(),
                data: TPMU_CAPABILITIES {
                    algorithms: data.into(),
                },
            },
            CapabilityData::Handles(data) => TPMS_CAPABILITY_DATA {
                capability: CapabilityType::Handles.into(),
                data: TPMU_CAPABILITIES {
                    handles: data.into(),
                },
            },
            CapabilityData::Commands(data) => TPMS_CAPABILITY_DATA {
                capability: CapabilityType::Command.into(),
                data: TPMU_CAPABILITIES {
                    command: data.into(),
                },
            },
            CapabilityData::PpCommands(data) => TPMS_CAPABILITY_DATA {
                capability: CapabilityType::PpCommands.into(),
                data: TPMU_CAPABILITIES {
                    ppCommands: data.into(),
                },
            },
            CapabilityData::AuditCommands(data) => TPMS_CAPABILITY_DATA {
                capability: CapabilityType::AuditCommands.into(),
                data: TPMU_CAPABILITIES {
                    auditCommands: data.into(),
                },
            },
            CapabilityData::AssignedPcr(data) => TPMS_CAPABILITY_DATA {
                capability: CapabilityType::AssignedPcr.into(),
                data: TPMU_CAPABILITIES {
                    assignedPCR: data.into(),
                },
            },
            CapabilityData::TpmProperties(data) => TPMS_CAPABILITY_DATA {
                capability: CapabilityType::TpmProperties.into(),
                data: TPMU_CAPABILITIES {
                    tpmProperties: data.into(),
                },
            },
            CapabilityData::PcrProperties(data) => TPMS_CAPABILITY_DATA {
                capability: CapabilityType::PcrProperties.into(),
                data: TPMU_CAPABILITIES {
                    pcrProperties: data.into(),
                },
            },
            CapabilityData::EccCurves(data) => TPMS_CAPABILITY_DATA {
                capability: CapabilityType::EccCurves.into(),
                data: TPMU_CAPABILITIES {
                    eccCurves: data.into(),
                },
            },
        }
    }
}

impl TryFrom<TPMS_CAPABILITY_DATA> for CapabilityData {
    type Error = Error;

    fn try_from(tpms_capability_data: TPMS_CAPABILITY_DATA) -> Result<Self> {
        // SAFETY: This is a C union, and Rust wants us to make sure we're using the correct item.
        // These unsafe blocks are fine because we ensure the correct type is used.
        match CapabilityType::try_from(tpms_capability_data.capability)? {
            CapabilityType::Algorithms => Ok(CapabilityData::Algorithms(
                unsafe { tpms_capability_data.data.algorithms }.try_into()?,
            )),
            CapabilityType::Handles => Ok(CapabilityData::Handles(
                unsafe { tpms_capability_data.data.handles }.try_into()?,
            )),
            CapabilityType::Command => Ok(CapabilityData::Commands(
                unsafe { tpms_capability_data.data.command }.try_into()?,
            )),
            CapabilityType::PpCommands => Ok(CapabilityData::PpCommands(
                unsafe { tpms_capability_data.data.ppCommands }.try_into()?,
            )),
            CapabilityType::AuditCommands => Ok(CapabilityData::AuditCommands(
                unsafe { tpms_capability_data.data.auditCommands }.try_into()?,
            )),
            CapabilityType::AssignedPcr => Ok(CapabilityData::AssignedPcr(
                unsafe { tpms_capability_data.data.assignedPCR }.try_into()?,
            )),
            CapabilityType::TpmProperties => Ok(CapabilityData::TpmProperties(
                unsafe { tpms_capability_data.data.tpmProperties }.try_into()?,
            )),
            CapabilityType::PcrProperties => Ok(CapabilityData::PcrProperties(
                unsafe { tpms_capability_data.data.pcrProperties }.try_into()?,
            )),
            CapabilityType::EccCurves => Ok(CapabilityData::EccCurves(
                unsafe { tpms_capability_data.data.eccCurves }.try_into()?,
            )),
            CapabilityType::AuthPolicies => {
                error!("AuthPolicies capability type is currently not supported");
                Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam))
            }
            CapabilityType::Act => {
                error!("Act capability type is currently not supported");
                Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam))
            }
        }
    }
}
