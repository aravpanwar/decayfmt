// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{
        TPM2_CC_AC_GetCapability, TPM2_CC_AC_Send, TPM2_CC_ActivateCredential, TPM2_CC_Certify,
        TPM2_CC_CertifyCreation, TPM2_CC_ChangeEPS, TPM2_CC_ChangePPS, TPM2_CC_Clear,
        TPM2_CC_ClearControl, TPM2_CC_ClockRateAdjust, TPM2_CC_ClockSet, TPM2_CC_Commit,
        TPM2_CC_ContextLoad, TPM2_CC_ContextSave, TPM2_CC_Create, TPM2_CC_CreateLoaded,
        TPM2_CC_CreatePrimary, TPM2_CC_DictionaryAttackLockReset,
        TPM2_CC_DictionaryAttackParameters, TPM2_CC_Duplicate, TPM2_CC_ECC_Parameters,
        TPM2_CC_ECDH_KeyGen, TPM2_CC_ECDH_ZGen, TPM2_CC_EC_Ephemeral, TPM2_CC_EncryptDecrypt,
        TPM2_CC_EncryptDecrypt2, TPM2_CC_EventSequenceComplete, TPM2_CC_EvictControl,
        TPM2_CC_FieldUpgradeData, TPM2_CC_FieldUpgradeStart, TPM2_CC_FirmwareRead,
        TPM2_CC_FlushContext, TPM2_CC_GetCapability, TPM2_CC_GetCommandAuditDigest,
        TPM2_CC_GetRandom, TPM2_CC_GetSessionAuditDigest, TPM2_CC_GetTestResult, TPM2_CC_GetTime,
        TPM2_CC_HMAC_Start, TPM2_CC_Hash, TPM2_CC_HashSequenceStart, TPM2_CC_HierarchyChangeAuth,
        TPM2_CC_HierarchyControl, TPM2_CC_Import, TPM2_CC_IncrementalSelfTest, TPM2_CC_Load,
        TPM2_CC_LoadExternal, TPM2_CC_MakeCredential, TPM2_CC_NV_Certify, TPM2_CC_NV_ChangeAuth,
        TPM2_CC_NV_DefineSpace, TPM2_CC_NV_Extend, TPM2_CC_NV_GlobalWriteLock,
        TPM2_CC_NV_Increment, TPM2_CC_NV_Read, TPM2_CC_NV_ReadLock, TPM2_CC_NV_ReadPublic,
        TPM2_CC_NV_SetBits, TPM2_CC_NV_UndefineSpace, TPM2_CC_NV_UndefineSpaceSpecial,
        TPM2_CC_NV_Write, TPM2_CC_NV_WriteLock, TPM2_CC_ObjectChangeAuth, TPM2_CC_PCR_Allocate,
        TPM2_CC_PCR_Event, TPM2_CC_PCR_Extend, TPM2_CC_PCR_Read, TPM2_CC_PCR_Reset,
        TPM2_CC_PCR_SetAuthPolicy, TPM2_CC_PCR_SetAuthValue, TPM2_CC_PP_Commands,
        TPM2_CC_PolicyAuthValue, TPM2_CC_PolicyAuthorize, TPM2_CC_PolicyAuthorizeNV,
        TPM2_CC_PolicyCommandCode, TPM2_CC_PolicyCounterTimer, TPM2_CC_PolicyCpHash,
        TPM2_CC_PolicyDuplicationSelect, TPM2_CC_PolicyGetDigest, TPM2_CC_PolicyLocality,
        TPM2_CC_PolicyNV, TPM2_CC_PolicyNameHash, TPM2_CC_PolicyNvWritten, TPM2_CC_PolicyOR,
        TPM2_CC_PolicyPCR, TPM2_CC_PolicyPassword, TPM2_CC_PolicyPhysicalPresence,
        TPM2_CC_PolicyRestart, TPM2_CC_PolicySecret, TPM2_CC_PolicySigned, TPM2_CC_PolicyTemplate,
        TPM2_CC_PolicyTicket, TPM2_CC_Policy_AC_SendSelect, TPM2_CC_Quote, TPM2_CC_RSA_Decrypt,
        TPM2_CC_RSA_Encrypt, TPM2_CC_ReadClock, TPM2_CC_ReadPublic, TPM2_CC_Rewrap,
        TPM2_CC_SelfTest, TPM2_CC_SequenceComplete, TPM2_CC_SequenceUpdate,
        TPM2_CC_SetAlgorithmSet, TPM2_CC_SetCommandCodeAuditStatus, TPM2_CC_SetPrimaryPolicy,
        TPM2_CC_Shutdown, TPM2_CC_Sign, TPM2_CC_StartAuthSession, TPM2_CC_Startup,
        TPM2_CC_StirRandom, TPM2_CC_TestParms, TPM2_CC_Unseal, TPM2_CC_VerifySignature,
        TPM2_CC_ZGen_2Phase, TPM2_CC_HMAC,
    },
    tss2_esys::TPM2_CC,
    Error, Result, WrapperErrorKind,
};
use bitfield::bitfield;
use log::error;
use std::convert::TryFrom;

bitfield! {
    /// Bitfield representing the command code structure
    #[derive(Copy, Clone, Eq, PartialEq, Hash)]
    pub struct CommandCodeStructure(u32);
    impl Debug;

    _, set_command_index: 15, 0;
    pub command_index, _: 15, 0;
    pub reserved, _ : 28, 16; // Shall be zero
    _, set_vendor_specific: 29;
    pub vendor_specific, _: 29;
    pub res, _ : 31, 30; // Shall be zero
}

impl CommandCodeStructure {
    pub const NV_UNDEFINE_SPACE_SPECIAL: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_NV_UndefineSpaceSpecial);
    pub const EVICT_CONTROL: CommandCodeStructure = CommandCodeStructure(TPM2_CC_EvictControl);
    pub const HIERARCHY_CONTROL: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_HierarchyControl);
    pub const NV_UNDEFINE_SPACE: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_NV_UndefineSpace);
    pub const CHANGE_EPS: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ChangeEPS);
    pub const CHANGE_PPS: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ChangePPS);
    pub const CLEAR: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Clear);
    pub const CLEAR_CONTROL: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ClearControl);
    pub const CLOCK_SET: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ClockSet);
    pub const HIERARCHY_CHANGE_AUTH: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_HierarchyChangeAuth);
    pub const NV_DEFINE_SPACE: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_DefineSpace);
    pub const PCR_ALLOCATE: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PCR_Allocate);
    pub const PCR_SET_AUTH_POLICY: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PCR_SetAuthPolicy);
    pub const PP_COMMANDS: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PP_Commands);
    pub const SET_PRIMARY_POLICY: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_SetPrimaryPolicy);
    pub const FIELD_UPGRADE_START: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_FieldUpgradeStart);
    pub const CLOCK_RATE_ADJUST: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_ClockRateAdjust);
    pub const CREATE_PRIMARY: CommandCodeStructure = CommandCodeStructure(TPM2_CC_CreatePrimary);
    pub const NV_GLOBAL_WRITE_LOCK: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_NV_GlobalWriteLock);
    pub const GET_COMMAND_AUDIT_DIGEST: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_GetCommandAuditDigest);
    pub const NV_INCREMENT: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_Increment);
    pub const NV_SET_BITS: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_SetBits);
    pub const NV_EXTEND: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_Extend);
    pub const NV_WRITE: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_Write);
    pub const NV_WRITE_LOCK: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_WriteLock);
    pub const DICTIONARY_ATTACK_LOCK_RESET: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_DictionaryAttackLockReset);
    pub const DICTIONARY_ATTACK_PARAMETERS: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_DictionaryAttackParameters);
    pub const NV_CHANGE_AUTH: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_ChangeAuth);
    pub const PCR_EVENT: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PCR_Event);
    pub const PCR_RESET: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PCR_Reset);
    pub const SEQUENCE_COMPLETE: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_SequenceComplete);
    pub const SET_ALGORITHM_SET: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_SetAlgorithmSet);
    pub const SET_COMMAND_CODE_AUDIT_STATUS: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_SetCommandCodeAuditStatus);
    pub const FIELD_UPGRADE_DATA: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_FieldUpgradeData);
    pub const INCREMENTAL_SELF_TEST: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_IncrementalSelfTest);
    pub const SELF_TEST: CommandCodeStructure = CommandCodeStructure(TPM2_CC_SelfTest);
    pub const STARTUP: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Startup);
    pub const SHUTDOWN: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Shutdown);
    pub const STIR_RANDOM: CommandCodeStructure = CommandCodeStructure(TPM2_CC_StirRandom);
    pub const ACTIVATE_CREDENTIAL: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_ActivateCredential);
    pub const CERTIFY: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Certify);
    pub const POLICY_NV: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicyNV);
    pub const CERTIFY_CREATION: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_CertifyCreation);
    pub const DUPLICATE: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Duplicate);
    pub const GET_TIME: CommandCodeStructure = CommandCodeStructure(TPM2_CC_GetTime);
    pub const GET_SESSION_AUDIT_DIGEST: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_GetSessionAuditDigest);
    pub const NV_READ: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_Read);
    pub const NV_READ_LOCK: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_ReadLock);
    pub const OBJECT_CHANGE_AUTH: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_ObjectChangeAuth);
    pub const POLICY_SECRET: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicySecret);
    pub const REWRAP: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Rewrap);
    pub const CREATE: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Create);
    pub const ECDH_Z_GEN: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ECDH_ZGen);
    pub const HMAC: CommandCodeStructure = CommandCodeStructure(TPM2_CC_HMAC);
    pub const IMPORT: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Import);
    pub const LOAD: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Load);
    pub const QUOTE: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Quote);
    pub const RSA_DECRYPT: CommandCodeStructure = CommandCodeStructure(TPM2_CC_RSA_Decrypt);
    pub const HMAC_START: CommandCodeStructure = CommandCodeStructure(TPM2_CC_HMAC_Start);
    pub const SEQUENCE_UPDATE: CommandCodeStructure = CommandCodeStructure(TPM2_CC_SequenceUpdate);
    pub const SIGN: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Sign);
    pub const UNSEAL: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Unseal);
    pub const POLICY_SIGNED: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicySigned);
    pub const CONTEXT_LOAD: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ContextLoad);
    pub const CONTEXT_SAVE: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ContextSave);
    pub const ECDH_KEY_GEN: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ECDH_KeyGen);
    pub const ENCRYPT_DECRYPT: CommandCodeStructure = CommandCodeStructure(TPM2_CC_EncryptDecrypt);
    pub const FLUSH_CONTEXT: CommandCodeStructure = CommandCodeStructure(TPM2_CC_FlushContext);
    pub const LOAD_EXTERNAL: CommandCodeStructure = CommandCodeStructure(TPM2_CC_LoadExternal);
    pub const MAKE_CREDENTIAL: CommandCodeStructure = CommandCodeStructure(TPM2_CC_MakeCredential);
    pub const NV_READ_PUBLIC: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_ReadPublic);
    pub const POLICY_AUTHORIZE: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PolicyAuthorize);
    pub const POLICY_AUTH_VALUE: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PolicyAuthValue);
    pub const POLICY_COMMAND_CODE: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PolicyCommandCode);
    pub const POLICY_COUNTER_TIMER: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PolicyCounterTimer);
    pub const POLICY_CP_HASH: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicyCpHash);
    pub const POLICY_LOCALITY: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicyLocality);
    pub const POLICY_NAME_HASH: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicyNameHash);
    pub const POLICY_OR: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicyOR);
    pub const POLICY_TICKET: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicyTicket);
    pub const READ_PUBLIC: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ReadPublic);
    pub const RSA_ENCRYPT: CommandCodeStructure = CommandCodeStructure(TPM2_CC_RSA_Encrypt);
    pub const START_AUTH_SESSION: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_StartAuthSession);
    pub const VERIFY_SIGNATURE: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_VerifySignature);
    pub const ECC_PARAMETERS: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ECC_Parameters);
    pub const FIRMWARE_READ: CommandCodeStructure = CommandCodeStructure(TPM2_CC_FirmwareRead);
    pub const GET_CAPABILITY: CommandCodeStructure = CommandCodeStructure(TPM2_CC_GetCapability);
    pub const GET_RANDOM: CommandCodeStructure = CommandCodeStructure(TPM2_CC_GetRandom);
    pub const GET_TEST_RESULT: CommandCodeStructure = CommandCodeStructure(TPM2_CC_GetTestResult);
    pub const HASH: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Hash);
    pub const PCR_READ: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PCR_Read);
    pub const POLICY_PCR: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicyPCR);
    pub const POLICY_RESTART: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicyRestart);
    pub const READ_CLOCK: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ReadClock);
    pub const PCR_EXTEND: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PCR_Extend);
    pub const PCR_SET_AUTH_VALUE: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PCR_SetAuthValue);
    pub const NV_CERTIFY: CommandCodeStructure = CommandCodeStructure(TPM2_CC_NV_Certify);
    pub const EVENT_SEQUENCE_COMPLETE: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_EventSequenceComplete);
    pub const HASH_SEQUENCE_START: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_HashSequenceStart);
    pub const POLICY_PHYSICAL_PRESENCE: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PolicyPhysicalPresence);
    pub const POLICY_DUPLICATION_SELECT: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PolicyDuplicationSelect);
    pub const POLICY_GET_DIGEST: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PolicyGetDigest);
    pub const TEST_PARMS: CommandCodeStructure = CommandCodeStructure(TPM2_CC_TestParms);
    pub const COMMIT: CommandCodeStructure = CommandCodeStructure(TPM2_CC_Commit);
    pub const POLICY_PASSWORD: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicyPassword);
    pub const Z_GEN_2_PHASE: CommandCodeStructure = CommandCodeStructure(TPM2_CC_ZGen_2Phase);
    pub const EC_EPHEMERAL: CommandCodeStructure = CommandCodeStructure(TPM2_CC_EC_Ephemeral);
    pub const POLICY_NV_WRITTEN: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PolicyNvWritten);
    pub const POLICY_TEMPLATE: CommandCodeStructure = CommandCodeStructure(TPM2_CC_PolicyTemplate);
    pub const CREATE_LOADED: CommandCodeStructure = CommandCodeStructure(TPM2_CC_CreateLoaded);
    pub const POLICY_AUTHORIZE_NV: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_PolicyAuthorizeNV);
    pub const ENCRYPT_DECRYPT_2: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_EncryptDecrypt2);
    pub const AC_GET_CAPABILITY: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_AC_GetCapability);
    pub const AC_SEND: CommandCodeStructure = CommandCodeStructure(TPM2_CC_AC_Send);
    pub const POLICY_AC_SEND_SELECT: CommandCodeStructure =
        CommandCodeStructure(TPM2_CC_Policy_AC_SendSelect);
}

impl TryFrom<TPM2_CC> for CommandCodeStructure {
    type Error = Error;

    fn try_from(tpm2_cc: TPM2_CC) -> Result<Self> {
        let command_code_structure = CommandCodeStructure(tpm2_cc);
        if command_code_structure.vendor_specific() {
            error!("The command code is vendor specific and cannot be parsed");
            return Err(Error::local_error(WrapperErrorKind::UnsupportedParam));
        }
        if command_code_structure.reserved() != 0 || command_code_structure.res() != 0 {
            error!("Encountered non zero reserved bits");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(command_code_structure)
    }
}

impl From<CommandCodeStructure> for TPM2_CC {
    fn from(command_code_structure: CommandCodeStructure) -> Self {
        command_code_structure.0
    }
}
