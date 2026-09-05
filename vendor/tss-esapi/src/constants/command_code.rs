// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod structure;

use crate::{tss2_esys::TPM2_CC, Error, Result, WrapperErrorKind};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;
use structure::CommandCodeStructure;

/// Enum representing the command code constants.
///
/// # Details
/// This corresponds to the TPM2_CC constants.
#[derive(FromPrimitive, ToPrimitive, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CommandCode {
    NvUndefineSpaceSpecial = CommandCodeStructure::NV_UNDEFINE_SPACE_SPECIAL.0,
    EvictControl = CommandCodeStructure::EVICT_CONTROL.0,
    HierarchyControl = CommandCodeStructure::HIERARCHY_CONTROL.0,
    NvUndefineSpace = CommandCodeStructure::NV_UNDEFINE_SPACE.0,
    ChangeEps = CommandCodeStructure::CHANGE_EPS.0,
    ChangePps = CommandCodeStructure::CHANGE_PPS.0,
    Clear = CommandCodeStructure::CLEAR.0,
    ClearControl = CommandCodeStructure::CLEAR_CONTROL.0,
    ClockSet = CommandCodeStructure::CLOCK_SET.0,
    HierarchyChangeAuth = CommandCodeStructure::HIERARCHY_CHANGE_AUTH.0,
    NvDefineSpace = CommandCodeStructure::NV_DEFINE_SPACE.0,
    PcrAllocate = CommandCodeStructure::PCR_ALLOCATE.0,
    PcrSetAuthPolicy = CommandCodeStructure::PCR_SET_AUTH_POLICY.0,
    PpCommands = CommandCodeStructure::PP_COMMANDS.0,
    SetPrimaryPolicy = CommandCodeStructure::SET_PRIMARY_POLICY.0,
    FieldUpgradeStart = CommandCodeStructure::FIELD_UPGRADE_START.0,
    ClockRateAdjust = CommandCodeStructure::CLOCK_RATE_ADJUST.0,
    CreatePrimary = CommandCodeStructure::CREATE_PRIMARY.0,
    NvGlobalWriteLock = CommandCodeStructure::NV_GLOBAL_WRITE_LOCK.0,
    GetCommandAuditDigest = CommandCodeStructure::GET_COMMAND_AUDIT_DIGEST.0,
    NvIncrement = CommandCodeStructure::NV_INCREMENT.0,
    NvSetBits = CommandCodeStructure::NV_SET_BITS.0,
    NvExtend = CommandCodeStructure::NV_EXTEND.0,
    NvWrite = CommandCodeStructure::NV_WRITE.0,
    NvWriteLock = CommandCodeStructure::NV_WRITE_LOCK.0,
    DictionaryAttackLockReset = CommandCodeStructure::DICTIONARY_ATTACK_LOCK_RESET.0,
    DictionaryAttackParameters = CommandCodeStructure::DICTIONARY_ATTACK_PARAMETERS.0,
    NvChangeAuth = CommandCodeStructure::NV_CHANGE_AUTH.0,
    PcrEvent = CommandCodeStructure::PCR_EVENT.0,
    PcrReset = CommandCodeStructure::PCR_RESET.0,
    SequenceComplete = CommandCodeStructure::SEQUENCE_COMPLETE.0,
    SetAlgorithmSet = CommandCodeStructure::SET_ALGORITHM_SET.0,
    SetCommandCodeAuditStatus = CommandCodeStructure::SET_COMMAND_CODE_AUDIT_STATUS.0,
    FieldUpgradeData = CommandCodeStructure::FIELD_UPGRADE_DATA.0,
    IncrementalSelfTest = CommandCodeStructure::INCREMENTAL_SELF_TEST.0,
    SelfTest = CommandCodeStructure::SELF_TEST.0,
    Startup = CommandCodeStructure::STARTUP.0,
    Shutdown = CommandCodeStructure::SHUTDOWN.0,
    StirRandom = CommandCodeStructure::STIR_RANDOM.0,
    ActivateCredential = CommandCodeStructure::ACTIVATE_CREDENTIAL.0,
    Certify = CommandCodeStructure::CERTIFY.0,
    PolicyNv = CommandCodeStructure::POLICY_NV.0,
    CertifyCreation = CommandCodeStructure::CERTIFY_CREATION.0,
    Duplicate = CommandCodeStructure::DUPLICATE.0,
    GetTime = CommandCodeStructure::GET_TIME.0,
    GetSessionAuditDigest = CommandCodeStructure::GET_SESSION_AUDIT_DIGEST.0,
    NvRead = CommandCodeStructure::NV_READ.0,
    NvReadLock = CommandCodeStructure::NV_READ_LOCK.0,
    ObjectChangeAuth = CommandCodeStructure::OBJECT_CHANGE_AUTH.0,
    PolicySecret = CommandCodeStructure::POLICY_SECRET.0,
    Rewrap = CommandCodeStructure::REWRAP.0,
    Create = CommandCodeStructure::CREATE.0,
    EcdhZGen = CommandCodeStructure::ECDH_Z_GEN.0,
    Hmac = CommandCodeStructure::HMAC.0,
    Import = CommandCodeStructure::IMPORT.0,
    Load = CommandCodeStructure::LOAD.0,
    Quote = CommandCodeStructure::QUOTE.0,
    RsaDecrypt = CommandCodeStructure::RSA_DECRYPT.0,
    HmacStart = CommandCodeStructure::HMAC_START.0,
    SequenceUpdate = CommandCodeStructure::SEQUENCE_UPDATE.0,
    Sign = CommandCodeStructure::SIGN.0,
    Unseal = CommandCodeStructure::UNSEAL.0,
    PolicySigned = CommandCodeStructure::POLICY_SIGNED.0,
    ContextLoad = CommandCodeStructure::CONTEXT_LOAD.0,
    ContextSave = CommandCodeStructure::CONTEXT_SAVE.0,
    EcdhKeyGen = CommandCodeStructure::ECDH_KEY_GEN.0,
    EncryptDecrypt = CommandCodeStructure::ENCRYPT_DECRYPT.0,
    FlushContext = CommandCodeStructure::FLUSH_CONTEXT.0,
    LoadExternal = CommandCodeStructure::LOAD_EXTERNAL.0,
    MakeCredential = CommandCodeStructure::MAKE_CREDENTIAL.0,
    NvReadPublic = CommandCodeStructure::NV_READ_PUBLIC.0,
    PolicyAuthorize = CommandCodeStructure::POLICY_AUTHORIZE.0,
    PolicyAuthValue = CommandCodeStructure::POLICY_AUTH_VALUE.0,
    PolicyCommandCode = CommandCodeStructure::POLICY_COMMAND_CODE.0,
    PolicyCounterTimer = CommandCodeStructure::POLICY_COUNTER_TIMER.0,
    PolicyCpHash = CommandCodeStructure::POLICY_CP_HASH.0,
    PolicyLocality = CommandCodeStructure::POLICY_LOCALITY.0,
    PolicyNameHash = CommandCodeStructure::POLICY_NAME_HASH.0,
    PolicyOr = CommandCodeStructure::POLICY_OR.0,
    PolicyTicket = CommandCodeStructure::POLICY_TICKET.0,
    ReadPublic = CommandCodeStructure::READ_PUBLIC.0,
    RsaEncrypt = CommandCodeStructure::RSA_ENCRYPT.0,
    StartAuthSession = CommandCodeStructure::START_AUTH_SESSION.0,
    VerifySignature = CommandCodeStructure::VERIFY_SIGNATURE.0,
    EccParameters = CommandCodeStructure::ECC_PARAMETERS.0,
    FirmwareRead = CommandCodeStructure::FIRMWARE_READ.0,
    GetCapability = CommandCodeStructure::GET_CAPABILITY.0,
    GetRandom = CommandCodeStructure::GET_RANDOM.0,
    GetTestResult = CommandCodeStructure::GET_TEST_RESULT.0,
    Hash = CommandCodeStructure::HASH.0,
    PcrRead = CommandCodeStructure::PCR_READ.0,
    PolicyPcr = CommandCodeStructure::POLICY_PCR.0,
    PolicyRestart = CommandCodeStructure::POLICY_RESTART.0,
    ReadClock = CommandCodeStructure::READ_CLOCK.0,
    PcrExtend = CommandCodeStructure::PCR_EXTEND.0,
    PcrSetAuthValue = CommandCodeStructure::PCR_SET_AUTH_VALUE.0,
    NvCertify = CommandCodeStructure::NV_CERTIFY.0,
    EventSequenceComplete = CommandCodeStructure::EVENT_SEQUENCE_COMPLETE.0,
    HashSequenceStart = CommandCodeStructure::HASH_SEQUENCE_START.0,
    PolicyPhysicalPresence = CommandCodeStructure::POLICY_PHYSICAL_PRESENCE.0,
    PolicyDuplicationSelect = CommandCodeStructure::POLICY_DUPLICATION_SELECT.0,
    PolicyGetDigest = CommandCodeStructure::POLICY_GET_DIGEST.0,
    TestParms = CommandCodeStructure::TEST_PARMS.0,
    Commit = CommandCodeStructure::COMMIT.0,
    PolicyPassword = CommandCodeStructure::POLICY_PASSWORD.0,
    ZGen2Phase = CommandCodeStructure::Z_GEN_2_PHASE.0,
    EcEphemeral = CommandCodeStructure::EC_EPHEMERAL.0,
    PolicyNvWritten = CommandCodeStructure::POLICY_NV_WRITTEN.0,
    PolicyTemplate = CommandCodeStructure::POLICY_TEMPLATE.0,
    CreateLoaded = CommandCodeStructure::CREATE_LOADED.0,
    PolicyAuthorizeNv = CommandCodeStructure::POLICY_AUTHORIZE_NV.0,
    EncryptDecrypt2 = CommandCodeStructure::ENCRYPT_DECRYPT_2.0,
    AcGetCapability = CommandCodeStructure::AC_GET_CAPABILITY.0,
    AcSend = CommandCodeStructure::AC_SEND.0,
    PolicyAcSendSelect = CommandCodeStructure::POLICY_AC_SEND_SELECT.0,
}

impl TryFrom<TPM2_CC> for CommandCode {
    type Error = Error;

    fn try_from(tpm2_cc: TPM2_CC) -> Result<Self> {
        CommandCode::from_u32(CommandCodeStructure::try_from(tpm2_cc)?.0).ok_or_else(|| {
            error!("Value = {} did not match any Command Code", tpm2_cc);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

impl From<CommandCode> for TPM2_CC {
    fn from(command_code: CommandCode) -> Self {
        // The values are well defined so this cannot fail.
        command_code.to_u32().unwrap()
    }
}
