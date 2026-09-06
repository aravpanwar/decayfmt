// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_get_capability {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        constants::{tss::TPM2_PT_VENDOR_STRING_1, CapabilityType, PropertyTag},
        structures::CapabilityData,
    };

    #[test]
    fn test_get_capability() {
        let mut context = create_ctx_without_session();
        let (res, _more) = context
            .get_capability(CapabilityType::TpmProperties, TPM2_PT_VENDOR_STRING_1, 4)
            .unwrap();
        match res {
            CapabilityData::TpmProperties(props) => {
                assert_ne!(props.len(), 0);
            }
            _ => panic!("Invalid properties returned"),
        };
    }

    #[test]
    fn test_get_tpm_property() {
        let mut context = create_ctx_without_session();

        let rev = context
            .get_tpm_property(PropertyTag::Revision)
            .expect("Failed to call get_tpm_property")
            .expect("The TPM did not have a value for the Reveision property tag");
        assert_ne!(rev, 0);

        let year = context
            .get_tpm_property(PropertyTag::Year)
            .expect("Failed to call get_tpm_property")
            .expect("The TPM did not have a value for the Year property tag");
        assert_ne!(year, 0);
    }
}
