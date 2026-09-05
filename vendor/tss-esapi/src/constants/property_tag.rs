// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{constants::tss::*, tss2_esys::TPM2_PT, Error, Result, WrapperErrorKind};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

#[derive(FromPrimitive, ToPrimitive, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum PropertyTag {
    None = TPM2_PT_NONE,
    // Fixed
    FamilyIndicator = TPM2_PT_FAMILY_INDICATOR,
    Level = TPM2_PT_LEVEL,
    Revision = TPM2_PT_REVISION,
    DayOfYear = TPM2_PT_DAY_OF_YEAR,
    Year = TPM2_PT_YEAR,
    Manufacturer = TPM2_PT_MANUFACTURER,
    VendorString1 = TPM2_PT_VENDOR_STRING_1,
    VendorString2 = TPM2_PT_VENDOR_STRING_2,
    VendorString3 = TPM2_PT_VENDOR_STRING_3,
    VendorString4 = TPM2_PT_VENDOR_STRING_4,
    VendorTPMType = TPM2_PT_VENDOR_TPM_TYPE,
    FirmwareVersion1 = TPM2_PT_FIRMWARE_VERSION_1,
    FirmwareVersion2 = TPM2_PT_FIRMWARE_VERSION_2,
    InputBuffer = TPM2_PT_INPUT_BUFFER,
    HrTransientMin = TPM2_PT_HR_TRANSIENT_MIN,
    HrPersistentMin = TPM2_PT_HR_PERSISTENT_MIN,
    HrLoadedMin = TPM2_PT_HR_LOADED_MIN,
    ActiveSessionsMax = TPM2_PT_ACTIVE_SESSIONS_MAX,
    PcrCount = TPM2_PT_PCR_COUNT,
    PcrSelectMin = TPM2_PT_PCR_SELECT_MIN,
    ContextGapMax = TPM2_PT_CONTEXT_GAP_MAX,
    NvCountersMax = TPM2_PT_NV_COUNTERS_MAX,
    NvIndexMax = TPM2_PT_NV_INDEX_MAX,
    Memory = TPM2_PT_MEMORY,
    ClockUpdate = TPM2_PT_CLOCK_UPDATE,
    ContextHash = TPM2_PT_CONTEXT_HASH,
    ContextSym = TPM2_PT_CONTEXT_SYM,
    ContextSymSize = TPM2_PT_CONTEXT_SYM_SIZE,
    OrderlyCount = TPM2_PT_ORDERLY_COUNT,
    MaxCommandSize = TPM2_PT_MAX_COMMAND_SIZE,
    MaxResponseSize = TPM2_PT_MAX_RESPONSE_SIZE,
    MaxDigest = TPM2_PT_MAX_DIGEST,
    MaxObjectContext = TPM2_PT_MAX_OBJECT_CONTEXT,
    MaxSessionContext = TPM2_PT_MAX_SESSION_CONTEXT,
    PsFamilyIndicator = TPM2_PT_PS_FAMILY_INDICATOR,
    PsLevel = TPM2_PT_PS_LEVEL,
    PsRevision = TPM2_PT_PS_REVISION,
    PsDayOfYear = TPM2_PT_PS_DAY_OF_YEAR,
    PsYear = TPM2_PT_PS_YEAR,
    SplitMax = TPM2_PT_SPLIT_MAX,
    TotalCommands = TPM2_PT_TOTAL_COMMANDS,
    LibraryCommands = TPM2_PT_LIBRARY_COMMANDS,
    VendorCommands = TPM2_PT_VENDOR_COMMANDS,
    NvBufferMax = TPM2_PT_NV_BUFFER_MAX,
    Modes = TPM2_PT_MODES,
    MaxCapBuffer = TPM2_PT_MAX_CAP_BUFFER,
    // Variable
    Permanent = TPM2_PT_PERMANENT,
    StartupClear = TPM2_PT_STARTUP_CLEAR,
    HrNvIndex = TPM2_PT_HR_NV_INDEX,
    HrLoaded = TPM2_PT_HR_LOADED,
    HrLoadedAvail = TPM2_PT_HR_LOADED_AVAIL,
    HrActive = TPM2_PT_HR_ACTIVE,
    HrActiveAvail = TPM2_PT_HR_ACTIVE_AVAIL,
    HrTransientAvail = TPM2_PT_HR_TRANSIENT_AVAIL,
    HrPersistent = TPM2_PT_HR_PERSISTENT,
    HrPersistentAvail = TPM2_PT_HR_PERSISTENT_AVAIL,
    NvCounters = TPM2_PT_NV_COUNTERS,
    NvCountersAvail = TPM2_PT_NV_COUNTERS_AVAIL,
    AlgorithmSet = TPM2_PT_ALGORITHM_SET,
    LoadedCurves = TPM2_PT_LOADED_CURVES,
    LockoutCounter = TPM2_PT_LOCKOUT_COUNTER,
    MaxAuthFail = TPM2_PT_MAX_AUTH_FAIL,
    LockoutInterval = TPM2_PT_LOCKOUT_INTERVAL,
    LockoutRecovery = TPM2_PT_LOCKOUT_RECOVERY,
    WriteRecovery = TPM2_PT_NV_WRITE_RECOVERY,
    AuditCounter0 = TPM2_PT_AUDIT_COUNTER_0,
    AuditCounter1 = TPM2_PT_AUDIT_COUNTER_1,
}

impl From<PropertyTag> for TPM2_PT {
    fn from(property_tag: PropertyTag) -> TPM2_PT {
        // The values are well defined so this cannot fail.
        property_tag.to_u32().unwrap()
    }
}

impl TryFrom<TPM2_PT> for PropertyTag {
    type Error = Error;
    fn try_from(tpm_pt: TPM2_PT) -> Result<PropertyTag> {
        PropertyTag::from_u32(tpm_pt).ok_or_else(|| {
            error!("value = {} did not match any PropertyTag.", tpm_pt);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}
