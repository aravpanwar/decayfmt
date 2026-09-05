// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    constants::{tss::*, CommandCode},
    tss2_esys::TPM2_CC,
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tpm_command_code:ident, CommandCode::$command_code:ident) => {
        assert_eq!(
            $tpm_command_code,
            TPM2_CC::from(CommandCode::$command_code),
            "Failed to convert {} to TPM2_CC",
            std::stringify!(CommandCode::$command_code),
        );

        assert_eq!(
            CommandCode::$command_code,
            CommandCode::try_from($tpm_command_code).expect(&format!(
                "Failed to convert {} to a CommandCode",
                std::stringify!($tpm_command_code)
            )),
            "{} did not convert into {}",
            std::stringify!($tpm_command_code),
            std::stringify!(CommandCode::$command_code),
        )
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(
        TPM2_CC_NV_UndefineSpaceSpecial,
        CommandCode::NvUndefineSpaceSpecial
    );
    test_valid_conversion!(TPM2_CC_EvictControl, CommandCode::EvictControl);
    test_valid_conversion!(TPM2_CC_HierarchyControl, CommandCode::HierarchyControl);
    test_valid_conversion!(TPM2_CC_NV_UndefineSpace, CommandCode::NvUndefineSpace);
    test_valid_conversion!(TPM2_CC_ChangeEPS, CommandCode::ChangeEps);
    test_valid_conversion!(TPM2_CC_ChangePPS, CommandCode::ChangePps);
    test_valid_conversion!(TPM2_CC_Clear, CommandCode::Clear);
    test_valid_conversion!(TPM2_CC_ClearControl, CommandCode::ClearControl);
    test_valid_conversion!(TPM2_CC_ClockSet, CommandCode::ClockSet);
    test_valid_conversion!(
        TPM2_CC_HierarchyChangeAuth,
        CommandCode::HierarchyChangeAuth
    );
    test_valid_conversion!(TPM2_CC_NV_DefineSpace, CommandCode::NvDefineSpace);
    test_valid_conversion!(TPM2_CC_PCR_Allocate, CommandCode::PcrAllocate);
    test_valid_conversion!(TPM2_CC_PCR_SetAuthPolicy, CommandCode::PcrSetAuthPolicy);
    test_valid_conversion!(TPM2_CC_PP_Commands, CommandCode::PpCommands);
    test_valid_conversion!(TPM2_CC_SetPrimaryPolicy, CommandCode::SetPrimaryPolicy);
    test_valid_conversion!(TPM2_CC_FieldUpgradeStart, CommandCode::FieldUpgradeStart);
    test_valid_conversion!(TPM2_CC_ClockRateAdjust, CommandCode::ClockRateAdjust);
    test_valid_conversion!(TPM2_CC_CreatePrimary, CommandCode::CreatePrimary);
    test_valid_conversion!(TPM2_CC_NV_GlobalWriteLock, CommandCode::NvGlobalWriteLock);
    test_valid_conversion!(
        TPM2_CC_GetCommandAuditDigest,
        CommandCode::GetCommandAuditDigest
    );
    test_valid_conversion!(TPM2_CC_NV_Increment, CommandCode::NvIncrement);
    test_valid_conversion!(TPM2_CC_NV_SetBits, CommandCode::NvSetBits);
    test_valid_conversion!(TPM2_CC_NV_Extend, CommandCode::NvExtend);
    test_valid_conversion!(TPM2_CC_NV_Write, CommandCode::NvWrite);
    test_valid_conversion!(TPM2_CC_NV_WriteLock, CommandCode::NvWriteLock);
    test_valid_conversion!(
        TPM2_CC_DictionaryAttackLockReset,
        CommandCode::DictionaryAttackLockReset
    );
    test_valid_conversion!(
        TPM2_CC_DictionaryAttackParameters,
        CommandCode::DictionaryAttackParameters
    );
    test_valid_conversion!(TPM2_CC_NV_ChangeAuth, CommandCode::NvChangeAuth);
    test_valid_conversion!(TPM2_CC_PCR_Event, CommandCode::PcrEvent);
    test_valid_conversion!(TPM2_CC_PCR_Reset, CommandCode::PcrReset);
    test_valid_conversion!(TPM2_CC_SequenceComplete, CommandCode::SequenceComplete);
    test_valid_conversion!(TPM2_CC_SetAlgorithmSet, CommandCode::SetAlgorithmSet);
    test_valid_conversion!(
        TPM2_CC_SetCommandCodeAuditStatus,
        CommandCode::SetCommandCodeAuditStatus
    );
    test_valid_conversion!(TPM2_CC_FieldUpgradeData, CommandCode::FieldUpgradeData);
    test_valid_conversion!(
        TPM2_CC_IncrementalSelfTest,
        CommandCode::IncrementalSelfTest
    );
    test_valid_conversion!(TPM2_CC_SelfTest, CommandCode::SelfTest);
    test_valid_conversion!(TPM2_CC_Startup, CommandCode::Startup);
    test_valid_conversion!(TPM2_CC_Shutdown, CommandCode::Shutdown);
    test_valid_conversion!(TPM2_CC_StirRandom, CommandCode::StirRandom);
    test_valid_conversion!(TPM2_CC_ActivateCredential, CommandCode::ActivateCredential);
    test_valid_conversion!(TPM2_CC_Certify, CommandCode::Certify);
    test_valid_conversion!(TPM2_CC_PolicyNV, CommandCode::PolicyNv);
    test_valid_conversion!(TPM2_CC_CertifyCreation, CommandCode::CertifyCreation);
    test_valid_conversion!(TPM2_CC_Duplicate, CommandCode::Duplicate);
    test_valid_conversion!(TPM2_CC_GetTime, CommandCode::GetTime);
    test_valid_conversion!(
        TPM2_CC_GetSessionAuditDigest,
        CommandCode::GetSessionAuditDigest
    );
    test_valid_conversion!(TPM2_CC_NV_Read, CommandCode::NvRead);
    test_valid_conversion!(TPM2_CC_NV_ReadLock, CommandCode::NvReadLock);
    test_valid_conversion!(TPM2_CC_ObjectChangeAuth, CommandCode::ObjectChangeAuth);
    test_valid_conversion!(TPM2_CC_PolicySecret, CommandCode::PolicySecret);
    test_valid_conversion!(TPM2_CC_Rewrap, CommandCode::Rewrap);
    test_valid_conversion!(TPM2_CC_Create, CommandCode::Create);
    test_valid_conversion!(TPM2_CC_ECDH_ZGen, CommandCode::EcdhZGen);
    test_valid_conversion!(TPM2_CC_HMAC, CommandCode::Hmac);
    test_valid_conversion!(TPM2_CC_Import, CommandCode::Import);
    test_valid_conversion!(TPM2_CC_Load, CommandCode::Load);
    test_valid_conversion!(TPM2_CC_Quote, CommandCode::Quote);
    test_valid_conversion!(TPM2_CC_RSA_Decrypt, CommandCode::RsaDecrypt);
    test_valid_conversion!(TPM2_CC_HMAC_Start, CommandCode::HmacStart);
    test_valid_conversion!(TPM2_CC_SequenceUpdate, CommandCode::SequenceUpdate);
    test_valid_conversion!(TPM2_CC_Sign, CommandCode::Sign);
    test_valid_conversion!(TPM2_CC_Unseal, CommandCode::Unseal);
    test_valid_conversion!(TPM2_CC_PolicySigned, CommandCode::PolicySigned);
    test_valid_conversion!(TPM2_CC_ContextLoad, CommandCode::ContextLoad);
    test_valid_conversion!(TPM2_CC_ContextSave, CommandCode::ContextSave);
    test_valid_conversion!(TPM2_CC_ECDH_KeyGen, CommandCode::EcdhKeyGen);
    test_valid_conversion!(TPM2_CC_EncryptDecrypt, CommandCode::EncryptDecrypt);
    test_valid_conversion!(TPM2_CC_FlushContext, CommandCode::FlushContext);
    test_valid_conversion!(TPM2_CC_LoadExternal, CommandCode::LoadExternal);
    test_valid_conversion!(TPM2_CC_MakeCredential, CommandCode::MakeCredential);
    test_valid_conversion!(TPM2_CC_NV_ReadPublic, CommandCode::NvReadPublic);
    test_valid_conversion!(TPM2_CC_PolicyAuthorize, CommandCode::PolicyAuthorize);
    test_valid_conversion!(TPM2_CC_PolicyAuthValue, CommandCode::PolicyAuthValue);
    test_valid_conversion!(TPM2_CC_PolicyCommandCode, CommandCode::PolicyCommandCode);
    test_valid_conversion!(TPM2_CC_PolicyCounterTimer, CommandCode::PolicyCounterTimer);
    test_valid_conversion!(TPM2_CC_PolicyCpHash, CommandCode::PolicyCpHash);
    test_valid_conversion!(TPM2_CC_PolicyLocality, CommandCode::PolicyLocality);
    test_valid_conversion!(TPM2_CC_PolicyNameHash, CommandCode::PolicyNameHash);
    test_valid_conversion!(TPM2_CC_PolicyOR, CommandCode::PolicyOr);
    test_valid_conversion!(TPM2_CC_PolicyTicket, CommandCode::PolicyTicket);
    test_valid_conversion!(TPM2_CC_ReadPublic, CommandCode::ReadPublic);
    test_valid_conversion!(TPM2_CC_RSA_Encrypt, CommandCode::RsaEncrypt);
    test_valid_conversion!(TPM2_CC_StartAuthSession, CommandCode::StartAuthSession);
    test_valid_conversion!(TPM2_CC_VerifySignature, CommandCode::VerifySignature);
    test_valid_conversion!(TPM2_CC_ECC_Parameters, CommandCode::EccParameters);
    test_valid_conversion!(TPM2_CC_FirmwareRead, CommandCode::FirmwareRead);
    test_valid_conversion!(TPM2_CC_GetCapability, CommandCode::GetCapability);
    test_valid_conversion!(TPM2_CC_GetRandom, CommandCode::GetRandom);
    test_valid_conversion!(TPM2_CC_GetTestResult, CommandCode::GetTestResult);
    test_valid_conversion!(TPM2_CC_Hash, CommandCode::Hash);
    test_valid_conversion!(TPM2_CC_PCR_Read, CommandCode::PcrRead);
    test_valid_conversion!(TPM2_CC_PolicyPCR, CommandCode::PolicyPcr);
    test_valid_conversion!(TPM2_CC_PolicyRestart, CommandCode::PolicyRestart);
    test_valid_conversion!(TPM2_CC_ReadClock, CommandCode::ReadClock);
    test_valid_conversion!(TPM2_CC_PCR_Extend, CommandCode::PcrExtend);
    test_valid_conversion!(TPM2_CC_PCR_SetAuthValue, CommandCode::PcrSetAuthValue);
    test_valid_conversion!(TPM2_CC_NV_Certify, CommandCode::NvCertify);
    test_valid_conversion!(
        TPM2_CC_EventSequenceComplete,
        CommandCode::EventSequenceComplete
    );
    test_valid_conversion!(TPM2_CC_HashSequenceStart, CommandCode::HashSequenceStart);
    test_valid_conversion!(
        TPM2_CC_PolicyPhysicalPresence,
        CommandCode::PolicyPhysicalPresence
    );
    test_valid_conversion!(
        TPM2_CC_PolicyDuplicationSelect,
        CommandCode::PolicyDuplicationSelect
    );
    test_valid_conversion!(TPM2_CC_PolicyGetDigest, CommandCode::PolicyGetDigest);
    test_valid_conversion!(TPM2_CC_TestParms, CommandCode::TestParms);
    test_valid_conversion!(TPM2_CC_Commit, CommandCode::Commit);
    test_valid_conversion!(TPM2_CC_PolicyPassword, CommandCode::PolicyPassword);
    test_valid_conversion!(TPM2_CC_ZGen_2Phase, CommandCode::ZGen2Phase);
    test_valid_conversion!(TPM2_CC_EC_Ephemeral, CommandCode::EcEphemeral);
    test_valid_conversion!(TPM2_CC_PolicyNvWritten, CommandCode::PolicyNvWritten);
    test_valid_conversion!(TPM2_CC_PolicyTemplate, CommandCode::PolicyTemplate);
    test_valid_conversion!(TPM2_CC_CreateLoaded, CommandCode::CreateLoaded);
    test_valid_conversion!(TPM2_CC_PolicyAuthorizeNV, CommandCode::PolicyAuthorizeNv);
    test_valid_conversion!(TPM2_CC_EncryptDecrypt2, CommandCode::EncryptDecrypt2);
    test_valid_conversion!(TPM2_CC_AC_GetCapability, CommandCode::AcGetCapability);
    test_valid_conversion!(TPM2_CC_AC_Send, CommandCode::AcSend);
    test_valid_conversion!(
        TPM2_CC_Policy_AC_SendSelect,
        CommandCode::PolicyAcSendSelect
    );
}

#[test]
fn test_invalid_conversions() {
    // Unsupported Vendor specific
    const VENDOR_SPECIFIC: TPM2_CC = 0b00100000000000000000000000000001u32;
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam)),
        CommandCode::try_from(VENDOR_SPECIFIC),
        "Value indicating vendor specific command code did not produce expected error"
    );

    // Set bits in in places marked as reserved
    const RES: TPM2_CC = 0b10000000000000000000000000000001u32;
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        CommandCode::try_from(RES),
        "Value with bit set a place marked as reserved (res) did not produce expected error"
    );

    const RESERVED: TPM2_CC = 0b00000000000000010000000000000001u32;
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        CommandCode::try_from(RESERVED),
        "Value with bit set a place marked as reserved (reserved) did not produce expected error"
    );

    // Valid but non existing command code
    const NON_EXISTING: TPM2_CC = 0b00000000000000001111111111111111u32;
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        CommandCode::try_from(NON_EXISTING),
        "A value representing a non existing command code did not produce the expected error"
    );
}
