// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::{Into, TryFrom};
use tss_esapi::{
    constants::tss::{
        TPM2_AC_LAST, TPM2_HMAC_SESSION_LAST, TPM2_HT_AC, TPM2_HT_HMAC_SESSION,
        TPM2_HT_LOADED_SESSION, TPM2_HT_NV_INDEX, TPM2_HT_PCR, TPM2_HT_PERMANENT,
        TPM2_HT_PERSISTENT, TPM2_HT_POLICY_SESSION, TPM2_HT_SAVED_SESSION, TPM2_HT_TRANSIENT,
        TPM2_LOADED_SESSION_LAST, TPM2_NV_INDEX_LAST, TPM2_PCR_LAST, TPM2_PERMANENT_LAST,
        TPM2_PERSISTENT_LAST, TPM2_POLICY_SESSION_LAST, TPM2_TRANSIENT_LAST,
    },
    handles::{
        AttachedComponentTpmHandle, HmacSessionTpmHandle, LoadedSessionTpmHandle, NvIndexTpmHandle,
        PcrTpmHandle, PermanentTpmHandle, PersistentTpmHandle, PolicySessionTpmHandle,
        SavedSessionTpmHandle, TpmHandle, TransientTpmHandle,
    },
    tss2_esys::TPM2_HANDLE,
};

mod test_tpm_handles {
    use super::*;

    #[test]
    fn test_pcr_tpm_handle() {
        // Invalid (wrong type)
        let value_with_wrong_type: u32 = 0xFF000000;
        let _ = PcrTpmHandle::new(value_with_wrong_type).unwrap_err();
        // Invalid (not in range)
        let value_not_in_range = TPM2_PCR_LAST + 1;
        let _ = PcrTpmHandle::new(value_not_in_range).unwrap_err();
        // Valid
        let valid_value: u32 = TPM2_PCR_LAST;
        let _ = PcrTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_nv_index_tpm_handle() {
        // Invalid (wrong type)
        let value_with_wrong_type: u32 = 0xFF000000;
        let _ = NvIndexTpmHandle::new(value_with_wrong_type).unwrap_err();
        // Invalid (not in range)
        let value_not_in_range = TPM2_NV_INDEX_LAST + 1;
        let _ = NvIndexTpmHandle::new(value_not_in_range).unwrap_err();
        // Valid
        let valid_value: u32 = TPM2_NV_INDEX_LAST;
        let _ = NvIndexTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_hmac_session_tpm_handle() {
        // Invalid (wrong type)
        let value_with_wrong_type: u32 = 0xFF000000;
        let _ = HmacSessionTpmHandle::new(value_with_wrong_type).unwrap_err();
        // Invalid (not in range)
        let value_not_in_range = TPM2_HMAC_SESSION_LAST + 1;
        let _ = HmacSessionTpmHandle::new(value_not_in_range).unwrap_err();
        // Valid
        let valid_value: u32 = TPM2_HMAC_SESSION_LAST;
        let _ = HmacSessionTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_loaded_session_tpm_handle() {
        // Invalid (wrong type)
        let value_with_wrong_type: u32 = 0xFF000000;
        let _ = LoadedSessionTpmHandle::new(value_with_wrong_type).unwrap_err();
        // Invalid (not in range)
        let value_not_in_range = TPM2_LOADED_SESSION_LAST + 1;
        let _ = LoadedSessionTpmHandle::new(value_not_in_range).unwrap_err();
        // Valid
        let valid_value: u32 = TPM2_LOADED_SESSION_LAST;
        let _ = LoadedSessionTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_policy_session_tpm_handle() {
        // Invalid (wrong type)
        let value_with_wrong_type: u32 = 0xFF000000;
        let _ = PolicySessionTpmHandle::new(value_with_wrong_type).unwrap_err();
        // Invalid (not in range)
        let value_not_in_range = TPM2_POLICY_SESSION_LAST + 1;
        let _ = PolicySessionTpmHandle::new(value_not_in_range).unwrap_err();
        // Valid
        let valid_value: u32 = TPM2_POLICY_SESSION_LAST;
        let _ = PolicySessionTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_saved_session_tpm_handle() {
        // Invalid (wrong type)
        let value_with_wrong_type: u32 = 0xFF000000;
        let _ = SavedSessionTpmHandle::new(value_with_wrong_type).unwrap_err();
        // Invalid (not in range)
        let value_not_in_range = TPM2_POLICY_SESSION_LAST + 1;
        let _ = SavedSessionTpmHandle::new(value_not_in_range).unwrap_err();
        // Valid
        let valid_value: u32 = TPM2_POLICY_SESSION_LAST;
        let _ = SavedSessionTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_permanent_tpm_handle() {
        // Invalid (wrong type)
        let value_with_wrong_type: u32 = 0xFF000000;
        let _ = PermanentTpmHandle::new(value_with_wrong_type).unwrap_err();
        // Invalid (not in range)
        let value_not_in_range = TPM2_PERMANENT_LAST + 1;
        let _ = PermanentTpmHandle::new(value_not_in_range).unwrap_err();
        // Valid
        let valid_value: u32 = TPM2_PERMANENT_LAST;
        let _ = PermanentTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_transient_tpm_handle() {
        // Invalid (wrong type)
        let value_with_wrong_type: u32 = 0xFF000000;
        let _ = TransientTpmHandle::new(value_with_wrong_type).unwrap_err();
        // Invalid (not in range)
        let value_not_in_range = TPM2_TRANSIENT_LAST + 1;
        let _ = TransientTpmHandle::new(value_not_in_range).unwrap_err();
        // Valid
        let valid_value: u32 = TPM2_TRANSIENT_LAST;
        let _ = TransientTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_persistent_tpm_handle() {
        // Invalid (wrong type)
        let value_with_wrong_type: u32 = 0xFF000000;
        let _ = PersistentTpmHandle::new(value_with_wrong_type).unwrap_err();
        // Invalid (not in range)
        let value_not_in_range = TPM2_PERSISTENT_LAST + 1;
        let _ = PersistentTpmHandle::new(value_not_in_range).unwrap_err();
        // Valid
        let valid_value: u32 = TPM2_PERSISTENT_LAST;
        let _ = PersistentTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_ac_tpm_handle() {
        // Invalid (wrong type)
        let value_with_wrong_type: u32 = 0xFF000000;
        let _ = AttachedComponentTpmHandle::new(value_with_wrong_type).unwrap_err();
        // Invalid (not in range)
        let value_not_in_range = TPM2_AC_LAST + 1;
        let _ = AttachedComponentTpmHandle::new(value_not_in_range).unwrap_err();
        // Valid
        let valid_value: u32 = TPM2_AC_LAST;
        let _ = AttachedComponentTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_general_tpm_handle_from_tss_tpm_handle_conversion() {
        let invalid_value: TPM2_HANDLE = 0xFFFFFFFF;
        let _ = TpmHandle::try_from(invalid_value).unwrap_err();

        assert_eq!(
            TpmHandle::try_from(TPM2_PCR_LAST).unwrap(),
            TpmHandle::Pcr(PcrTpmHandle::new(TPM2_PCR_LAST).unwrap())
        );

        assert_eq!(
            TpmHandle::try_from(TPM2_NV_INDEX_LAST).unwrap(),
            TpmHandle::NvIndex(NvIndexTpmHandle::new(TPM2_NV_INDEX_LAST).unwrap())
        );

        assert_eq!(
            TpmHandle::try_from(TPM2_HMAC_SESSION_LAST).unwrap(),
            TpmHandle::HmacSession(HmacSessionTpmHandle::new(TPM2_HMAC_SESSION_LAST).unwrap())
        );

        // TPM2_HT_LOADED_SESSION is the same as TPM2_HT_HMAC_SESSION

        assert_eq!(
            TpmHandle::try_from(TPM2_POLICY_SESSION_LAST).unwrap(),
            TpmHandle::PolicySession(
                PolicySessionTpmHandle::new(TPM2_POLICY_SESSION_LAST).unwrap()
            )
        );

        // TPM2_HT_SAVED_SESSION is the same as TPM2_HT_POLICY_SESSION

        assert_eq!(
            TpmHandle::try_from(TPM2_PERMANENT_LAST).unwrap(),
            TpmHandle::Permanent(PermanentTpmHandle::new(TPM2_PERMANENT_LAST).unwrap())
        );

        assert_eq!(
            TpmHandle::try_from(TPM2_TRANSIENT_LAST).unwrap(),
            TpmHandle::Transient(TransientTpmHandle::new(TPM2_TRANSIENT_LAST).unwrap())
        );

        assert_eq!(
            TpmHandle::try_from(TPM2_PERSISTENT_LAST).unwrap(),
            TpmHandle::Persistent(PersistentTpmHandle::new(TPM2_PERSISTENT_LAST).unwrap())
        );

        assert_eq!(
            TpmHandle::try_from(TPM2_AC_LAST).unwrap(),
            TpmHandle::AttachedComponent(AttachedComponentTpmHandle::new(TPM2_AC_LAST).unwrap())
        );
    }

    #[test]
    fn test_general_tpm_handle_to_tss_tpm_handle_conversion() {
        {
            let expected = u32::from_be_bytes([TPM2_HT_PCR, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::Pcr(PcrTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_NV_INDEX, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::NvIndex(NvIndexTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_HMAC_SESSION, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::HmacSession(HmacSessionTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_LOADED_SESSION, 0x00, 0x00, 0x01]);
            let tpm_handle =
                TpmHandle::LoadedSession(LoadedSessionTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_POLICY_SESSION, 0x00, 0x00, 0x01]);
            let tpm_handle =
                TpmHandle::PolicySession(PolicySessionTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_SAVED_SESSION, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::SavedSession(SavedSessionTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_PERMANENT, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::Permanent(PermanentTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_TRANSIENT, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::Transient(TransientTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_PERSISTENT, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::Persistent(PersistentTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_AC, 0x00, 0x00, 0x01]);
            let tpm_handle =
                TpmHandle::AttachedComponent(AttachedComponentTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }
    }
}
