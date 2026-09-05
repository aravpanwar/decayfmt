// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_nv_define_space {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Provision},
        structures::NvPublicBuilder,
    };

    #[test]
    fn test_nv_define_space_failures() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500015).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        // Create platform nv public.
        let platform_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_pp_write(true)
            .with_pp_read(true)
            .with_platform_create(true)
            .build()
            .expect("Failed to create platform nv index attributes");

        let platform_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(platform_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        // Fails because attributes dont match hierarchy auth.
        let _ = context
            .nv_define_space(Provision::Platform, None, owner_nv_public)
            .unwrap_err();

        let _ = context
            .nv_define_space(Provision::Owner, None, platform_nv_public)
            .unwrap_err();
    }

    #[test]
    fn test_nv_define_space() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500016).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for owner");

        // Create platform nv public.
        let platform_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_pp_write(true)
            .with_pp_read(true)
            .with_platform_create(true)
            .build()
            .expect("Failed to create platform nv index attributes");

        let platform_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(platform_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for platform");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        // If you see this line fail, you are likely running it against a live TPM.
        // On many TPMs, you will get error 0x00000185, indicating the Platform hierarchy to
        // be unavailable (because the system went to operating system)
        let platform_nv_index_handle = context
            .nv_define_space(Provision::Platform, None, platform_nv_public)
            .expect("Call to nv_define_space failed");

        context
            .nv_undefine_space(Provision::Platform, platform_nv_index_handle)
            .expect("Call to nv_undefine_space failed");
    }
}

mod test_nv_undefine_space {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Provision},
        structures::NvPublicBuilder,
    };

    #[test]
    fn test_nv_undefine_space() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500017).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for owner");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        // Succeeds
        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");
    }
}

mod test_nv_read_public {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Provision},
        structures::NvPublicBuilder,
    };

    #[test]
    fn test_nv_read_public() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500019).unwrap();

        let nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let expected_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build the expected NvPublic");

        let nv_index_handle = context
            .nv_define_space(Provision::Owner, None, expected_nv_public.clone())
            .expect("Call to nv_define_space failed");

        let read_public_result = context.nv_read_public(nv_index_handle);

        context
            .nv_undefine_space(Provision::Owner, nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        // Report error
        if let Err(e) = read_public_result {
            panic!("Failed to read public of nv index: {}", e);
        }

        // Check result.
        let (actual_nv_public, _name) = read_public_result.unwrap();
        assert_eq!(expected_nv_public, actual_nv_public);
    }
}

mod test_nv_write {
    use crate::common::create_ctx_with_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{
            algorithm::HashingAlgorithm,
            resource_handles::{NvAuth, Provision},
        },
        structures::{MaxNvBuffer, NvPublicBuilder},
    };
    #[test]
    fn test_nv_write() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500018).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for owner");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        // Use owner authorization
        let write_result = context.nv_write(
            NvAuth::Owner,
            owner_nv_index_handle,
            MaxNvBuffer::try_from([1, 2, 3, 4, 5, 6, 7].to_vec()).unwrap(),
            0,
        );

        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        if let Err(e) = write_result {
            panic!("Failed to perform nv write: {}", e);
        }
    }
}

mod test_nv_read {
    use crate::common::create_ctx_with_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{
            algorithm::HashingAlgorithm,
            resource_handles::{NvAuth, Provision},
        },
        structures::{MaxNvBuffer, NvPublicBuilder},
    };
    #[test]
    fn test_nv_read() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500020).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for owner");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        let value = [1, 2, 3, 4, 5, 6, 7];
        let expected_data =
            MaxNvBuffer::try_from(value.to_vec()).expect("Failed to create MaxBuffer from data");

        // Write the data using Owner authorization
        let write_result = context.nv_write(
            NvAuth::Owner,
            owner_nv_index_handle,
            expected_data.clone(),
            0,
        );
        // read data using owner authorization
        let read_result =
            context.nv_read(NvAuth::Owner, owner_nv_index_handle, value.len() as u16, 0);
        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        // Report error
        if let Err(e) = write_result {
            panic!("Failed to perform nv write: {}", e);
        }
        if let Err(e) = read_result {
            panic!("Failed to read public of nv index: {}", e);
        }

        // Check result.
        let actual_data = read_result.unwrap();
        assert_eq!(expected_data, actual_data);
    }
}

mod test_nv_increment {
    use crate::common::create_ctx_with_session;
    use std::convert::TryInto;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        constants::nv_index_type::NvIndexType,
        handles::NvIndexTpmHandle,
        interface_types::{
            algorithm::HashingAlgorithm,
            resource_handles::{NvAuth, Provision},
        },
        structures::NvPublicBuilder,
    };
    #[test]
    fn test_nv_increment() {
        let mut context = create_ctx_with_session();
        let nv_index = NvIndexTpmHandle::new(0x01500021).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .with_nv_index_type(NvIndexType::Counter)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(8)
            .build()
            .expect("Failed to build NvPublic for owner");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        // Increment the counter using Owner authorization. This call initializes the counter
        let increment_result = context.nv_increment(NvAuth::Owner, owner_nv_index_handle);
        if let Err(e) = increment_result {
            panic!("Failed to perform nv increment: {}", e);
        }

        // Read the counter using owner authorization (first call)
        let read_result_first_value = context.nv_read(NvAuth::Owner, owner_nv_index_handle, 8, 0);

        // Increment the counter using Owner authorization (second increment)
        let increment_result = context.nv_increment(NvAuth::Owner, owner_nv_index_handle);
        if let Err(e) = increment_result {
            panic!("Failed to perform nv increment: {}", e);
        }

        // Read the counter using owner authorization
        let read_result_second_value = context.nv_read(NvAuth::Owner, owner_nv_index_handle, 8, 0);

        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        // Report error
        if let Err(e) = read_result_first_value {
            panic!("Failed to read public of nv index: {}", e);
        }
        if let Err(e) = read_result_second_value {
            panic!("Failed to read public of nv index: {}", e);
        }

        // Check result.
        let first_value = u64::from_be_bytes(
            read_result_first_value
                .unwrap()
                .to_vec()
                .try_into()
                .unwrap(),
        );
        let second_value = u64::from_be_bytes(
            read_result_second_value
                .unwrap()
                .to_vec()
                .try_into()
                .unwrap(),
        );
        assert_eq!(first_value + 1, second_value);
    }
}
