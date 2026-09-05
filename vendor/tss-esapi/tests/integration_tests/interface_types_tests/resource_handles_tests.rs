// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    handles::{AuthHandle, NvIndexHandle, ObjectHandle, PermanentTpmHandle, TpmHandle},
    interface_types::resource_handles::{
        Clear, Enables, Endorsement, Hierarchy, HierarchyAuth, Lockout, NvAuth, Owner, Platform,
        Provision,
    },
    tss2_esys::ESYS_TR,
};

mod test_hierarchy {
    use super::*;
    #[test]
    fn test_conversions() {
        let test_conversion =
            |hierarchy: Hierarchy, tpm_rh: TpmHandle, esys_rh: ObjectHandle, name: &str| {
                assert_eq!(ObjectHandle::from(hierarchy), esys_rh);
                assert_eq!(TpmHandle::from(hierarchy), tpm_rh);
                let from_esys_rh = Hierarchy::try_from(esys_rh).unwrap_or_else(|_| {
                    panic!("Failed to create Hierarchy from ESYS_TR_RH={}", name)
                });
                assert_eq!(from_esys_rh, hierarchy);
                assert_eq!(ObjectHandle::from(from_esys_rh), esys_rh);
                assert_eq!(TpmHandle::from(from_esys_rh), tpm_rh);
                let from_tpm_rh = Hierarchy::try_from(tpm_rh)
                    .unwrap_or_else(|_| panic!("Failed to create Hierarchy from TPM2_RH={}", name));
                assert_eq!(from_tpm_rh, hierarchy);
                assert_eq!(ObjectHandle::from(from_tpm_rh), esys_rh);
                assert_eq!(TpmHandle::from(from_tpm_rh), tpm_rh);
            };

        test_conversion(
            Hierarchy::Owner,
            TpmHandle::Permanent(PermanentTpmHandle::Owner),
            ObjectHandle::Owner,
            "OWNER",
        );
        test_conversion(
            Hierarchy::Platform,
            TpmHandle::Permanent(PermanentTpmHandle::Platform),
            ObjectHandle::Platform,
            "PLATFORM",
        );
        test_conversion(
            Hierarchy::Endorsement,
            TpmHandle::Permanent(PermanentTpmHandle::Endorsement),
            ObjectHandle::Endorsement,
            "ENDORSEMENT",
        );
        test_conversion(
            Hierarchy::Null,
            TpmHandle::Permanent(PermanentTpmHandle::Null),
            ObjectHandle::Null,
            "NULL",
        );
    }
}

mod test_enables {
    use super::*;
    #[test]
    fn test_conversions() {
        let test_conversion =
            |enables: Enables, tpm_rh: TpmHandle, esys_rh: ObjectHandle, name: &str| {
                assert_eq!(ObjectHandle::from(enables), esys_rh);
                assert_eq!(TpmHandle::from(enables), tpm_rh);
                let from_esys_rh = Enables::try_from(esys_rh).unwrap_or_else(|_| {
                    panic!("Failed to create Enables from ESYS_TR_RH={}", name)
                });
                assert_eq!(from_esys_rh, enables);
                assert_eq!(ObjectHandle::from(from_esys_rh), esys_rh);
                assert_eq!(TpmHandle::from(from_esys_rh), tpm_rh);
                let from_tpm_rh = Enables::try_from(tpm_rh)
                    .unwrap_or_else(|_| panic!("Failed to create Enables from TPM2_RH={}", name));
                assert_eq!(from_tpm_rh, enables);
                assert_eq!(ObjectHandle::from(from_tpm_rh), esys_rh);
                assert_eq!(TpmHandle::from(from_tpm_rh), tpm_rh);
            };

        test_conversion(
            Enables::Owner,
            TpmHandle::Permanent(PermanentTpmHandle::Owner),
            ObjectHandle::Owner,
            "OWNER",
        );
        test_conversion(
            Enables::Platform,
            TpmHandle::Permanent(PermanentTpmHandle::Platform),
            ObjectHandle::Platform,
            "PLATFORM",
        );
        test_conversion(
            Enables::Endorsement,
            TpmHandle::Permanent(PermanentTpmHandle::Endorsement),
            ObjectHandle::Endorsement,
            "ENDORSEMENT",
        );
        test_conversion(
            Enables::Endorsement,
            TpmHandle::Permanent(PermanentTpmHandle::Endorsement),
            ObjectHandle::Endorsement,
            "PLATFORM_NV",
        );
        test_conversion(
            Enables::Null,
            TpmHandle::Permanent(PermanentTpmHandle::Null),
            ObjectHandle::Null,
            "NULL",
        );
    }
}

mod test_hierarchy_auth {
    use super::*;
    #[test]
    fn test_conversions() {
        let test_conversion = |hierarchy_auth: HierarchyAuth,
                               tpm_rh: TpmHandle,
                               esys_rh: ObjectHandle,
                               name: &str| {
            assert_eq!(ObjectHandle::from(hierarchy_auth), esys_rh);
            assert_eq!(TpmHandle::from(hierarchy_auth), tpm_rh);
            let from_esys_rh = HierarchyAuth::try_from(esys_rh).unwrap_or_else(|_| {
                panic!("Failed to create HierarchyAuth from ESYS_TR_RH={}", name)
            });
            assert_eq!(from_esys_rh, hierarchy_auth);
            assert_eq!(ObjectHandle::from(from_esys_rh), esys_rh);
            assert_eq!(TpmHandle::from(from_esys_rh), tpm_rh);
            let from_tpm_rh = HierarchyAuth::try_from(tpm_rh)
                .unwrap_or_else(|_| panic!("Failed to create HierarchyAuth from TPM2_RH={}", name));
            assert_eq!(from_tpm_rh, hierarchy_auth);
            assert_eq!(ObjectHandle::from(from_tpm_rh), esys_rh);
            assert_eq!(TpmHandle::from(from_tpm_rh), tpm_rh);
        };

        test_conversion(
            HierarchyAuth::Owner,
            TpmHandle::Permanent(PermanentTpmHandle::Owner),
            ObjectHandle::Owner,
            "OWNER",
        );
        test_conversion(
            HierarchyAuth::Platform,
            TpmHandle::Permanent(PermanentTpmHandle::Platform),
            ObjectHandle::Platform,
            "PLATFORM",
        );
        test_conversion(
            HierarchyAuth::Endorsement,
            TpmHandle::Permanent(PermanentTpmHandle::Endorsement),
            ObjectHandle::Endorsement,
            "ENDORSEMENT",
        );
        test_conversion(
            HierarchyAuth::Lockout,
            TpmHandle::Permanent(PermanentTpmHandle::Lockout),
            ObjectHandle::Lockout,
            "LOCKOUT",
        );
    }
}

mod test_platform {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(AuthHandle::from(Platform::Platform), AuthHandle::Platform);
        assert_eq!(
            Platform::try_from(AuthHandle::Platform)
                .expect("Failed to convert AuthHandle into Platform"),
            Platform::Platform
        );
    }
}

mod test_owner {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(ObjectHandle::from(Owner::Owner), ObjectHandle::Owner);
        assert_eq!(ObjectHandle::from(Owner::Null), ObjectHandle::Null);
        assert_eq!(
            Owner::try_from(ObjectHandle::Owner)
                .expect("Failed to convert TpmConstantHandle into Owner"),
            Owner::Owner
        );
        assert_eq!(
            Owner::try_from(ObjectHandle::Null)
                .expect("Failed to convert TpmConstantHandle into Owner"),
            Owner::Null
        );
    }
}

mod test_endorsement {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(
            ObjectHandle::from(Endorsement::Endorsement),
            ObjectHandle::Endorsement
        );
        assert_eq!(ObjectHandle::from(Endorsement::Null), ObjectHandle::Null);
        assert_eq!(
            Endorsement::try_from(ObjectHandle::Endorsement)
                .expect("Failed to convert TpmConstantHandle into Endorsement"),
            Endorsement::Endorsement
        );
        assert_eq!(
            Endorsement::try_from(ObjectHandle::Null)
                .expect("Failed to convert TpmConstantHandle into Endorsement"),
            Endorsement::Null
        );
    }
}

mod test_provision {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(AuthHandle::from(Provision::Owner), AuthHandle::Owner);
        assert_eq!(AuthHandle::from(Provision::Platform), AuthHandle::Platform);
        assert_eq!(
            Provision::try_from(AuthHandle::Owner)
                .expect("Failed to convert AuthHandle into Provision"),
            Provision::Owner
        );
        assert_eq!(
            Provision::try_from(AuthHandle::Platform)
                .expect("Failed to convert AuthHandle into Provision"),
            Provision::Platform
        );
    }
}

mod test_clear {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(AuthHandle::from(Clear::Owner), AuthHandle::Owner);
        assert_eq!(AuthHandle::from(Clear::Platform), AuthHandle::Platform);
        assert_eq!(
            Clear::try_from(AuthHandle::Owner).expect("Failed to convert AuthHandle into Clear"),
            Clear::Owner
        );
        assert_eq!(
            Clear::try_from(AuthHandle::Platform)
                .expect("Failed to convert AuthHandle into Provision"),
            Clear::Platform
        );
    }
}

mod test_nv_auth {
    use super::*;

    #[test]
    fn test_conversions() {
        assert_eq!(AuthHandle::from(NvAuth::Platform), AuthHandle::Platform);
        assert_eq!(AuthHandle::from(NvAuth::Owner), AuthHandle::Owner);

        let esys_handle: ESYS_TR = 0x12345678;
        let nv_index_handle = NvIndexHandle::from(esys_handle);
        assert_eq!(
            AuthHandle::from(NvAuth::NvIndex(nv_index_handle)),
            AuthHandle::from(esys_handle)
        );

        assert_eq!(
            NvAuth::try_from(AuthHandle::Platform)
                .expect("Failed to convert AuthHandle into NvAuth"),
            NvAuth::Platform
        );
        assert_eq!(
            NvAuth::try_from(AuthHandle::Owner).expect("Failed to convert AuthHandle into NvAuth"),
            NvAuth::Owner
        );
        assert_eq!(
            NvAuth::try_from(AuthHandle::from(esys_handle))
                .expect("Failed to convert AuthHandle into NvAuth"),
            NvAuth::NvIndex(nv_index_handle)
        );
    }
}

mod test_lockout {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(ObjectHandle::from(Lockout::Lockout), ObjectHandle::Lockout);
        assert_eq!(
            Lockout::try_from(ObjectHandle::Lockout)
                .expect("Failed to convert TpmConstantHandle into Lockout"),
            Lockout::Lockout
        );
    }
}
