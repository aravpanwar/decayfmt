mod test_tr_from_tpm_public {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        constants::{tss::TPM2_NV_INDEX_FIRST, CapabilityType},
        handles::{NvIndexHandle, NvIndexTpmHandle, ObjectHandle},
        interface_types::{
            algorithm::HashingAlgorithm,
            resource_handles::{NvAuth, Provision},
            session_handles::AuthSession,
        },
        structures::{Auth, CapabilityData, MaxNvBuffer, NvPublicBuilder},
        tss2_esys::TPM2_HANDLE,
        Context,
    };

    use std::convert::TryFrom;

    fn remove_nv_index_handle_from_tpm(nv_index_tpm_handle: NvIndexTpmHandle, nv_auth: Provision) {
        let mut context = create_ctx_without_session();
        let mut property = TPM2_NV_INDEX_FIRST;
        while let Ok((capability_data, more_data_available)) =
            context.get_capability(CapabilityType::Handles, property, 1)
        {
            if let CapabilityData::Handles(nv_index_handles) = capability_data {
                if let Some(&retrieved_nv_index_tpm_handle) = nv_index_handles.first() {
                    if retrieved_nv_index_tpm_handle == nv_index_tpm_handle.into() {
                        let handle = context
                            .tr_from_tpm_public(nv_index_tpm_handle.into())
                            .map(NvIndexHandle::from)
                            .expect("Failed to get nv index from tpm");
                        context.execute_with_session(Some(AuthSession::Password), |ctx| {
                            ctx.nv_undefine_space(nv_auth, handle)
                                .expect("Failed to undefine space");
                        });
                        return;
                    }

                    if more_data_available {
                        property = TPM2_HANDLE::from(retrieved_nv_index_tpm_handle) + 1;
                    }
                }
            }

            if !more_data_available {
                return;
            }
        }
    }

    // Need to set the shEnable in the TPMA_STARTUP in order for this to work.
    #[ignore]
    #[test]
    fn test_tr_from_tpm_public_owner_auth() {
        let mut context = create_ctx_without_session();

        let nv_index_tpm_handle = NvIndexTpmHandle::new(0x01500021).unwrap();

        // closure for cleaning up if a call fails.
        let cleanup = |context: &mut Context,
                       e: tss_esapi::Error,
                       handle: NvIndexHandle,
                       fn_name: &str|
         -> tss_esapi::Error {
            // Set password authorization
            context
                .nv_undefine_space(Provision::Owner, handle)
                .expect("Call to nv_undefine_space failed");
            panic!("{} failed: {}", fn_name, e);
        };

        // Create nv public.
        let nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index_tpm_handle)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        let initial_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, nv_public)
            .unwrap();
        ///////////////////////////////////////////
        // Read the name from the tpm
        let (_expected_nv_public, expected_name) = context
            .nv_read_public(initial_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "nv_read_public"))
            .unwrap();
        ////////////////////////////////////////////////
        // Close the handle
        let mut handle_to_be_closed: ObjectHandle = initial_nv_index_handle.into();
        context
            .tr_close(&mut handle_to_be_closed)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "tr_close"))
            .unwrap();
        assert_eq!(handle_to_be_closed, ObjectHandle::None);
        ////////////////////////////////////////////////
        // Make Esys create a new ObjectHandle from the
        // data in the TPM.
        let new_nv_index_handle = context
            .tr_from_tpm_public(nv_index_tpm_handle.into())
            .expect("tr_from_tpm_public failed");
        ///////////////////////////////////////////////
        // Get name of the object using the new handle
        let actual_name = context
            .tr_get_name(new_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, new_nv_index_handle.into(), "tr_get_name"))
            .unwrap();
        //////////////////////////////////////////////
        // Remove undefine the space
        context
            .nv_undefine_space(Provision::Owner, new_nv_index_handle.into())
            .expect("Call to nv_undefine_space failed");

        assert_eq!(expected_name, actual_name);
    }

    #[test]
    fn test_tr_from_tpm_public_password_auth() {
        let nv_index_tpm_handle = NvIndexTpmHandle::new(0x01500022).unwrap();
        remove_nv_index_handle_from_tpm(nv_index_tpm_handle, Provision::Owner);

        let mut context = create_ctx_without_session();

        let auth = Auth::try_from(vec![
            10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        ])
        .expect("Failed to create auth");

        // closure for cleaning up if a call fails.
        let cleanup = |context: &mut Context,
                       e: tss_esapi::Error,
                       handle: NvIndexHandle,
                       fn_name: &str|
         -> tss_esapi::Error {
            // Set password authorization
            context.set_sessions((Some(AuthSession::Password), None, None));
            context
                .nv_undefine_space(Provision::Owner, handle)
                .expect("Failed to call nv_undefine_space");
            panic!("{} failed: {}", fn_name, e);
        };

        // Create nv public.
        let nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_auth_write(true)
            .with_auth_read(true)
            .build()
            .expect("Failed to create auth nv index attributes");

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index_tpm_handle)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build nv public");
        ///////////////////////////////////////////////////////////////
        // Define space
        //
        // Set password authorization when creating the space.
        context.set_sessions((Some(AuthSession::Password), None, None));
        let initial_nv_index_handle = context
            .nv_define_space(Provision::Owner, Some(auth), nv_public)
            .expect("Failed to call nv_define_space");
        ///////////////////////////////////////////////////////////////
        // Read the name from the tpm
        //
        // No password authorization.
        context.clear_sessions();
        let (_expected_nv_public, expected_name) = context
            .nv_read_public(initial_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "nv_read_public"))
            .expect("Failed to call nv_read_public");
        ///////////////////////////////////////////////////////////////
        // Close the esys handle (remove all meta data).
        //
        let mut handle_to_be_closed: ObjectHandle = initial_nv_index_handle.into();
        context
            .tr_close(&mut handle_to_be_closed)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "tr_close"))
            .expect("Failed to call tr_close");
        assert_eq!(handle_to_be_closed, ObjectHandle::None);
        // The value of the handle_to_be_closed will be set to a 'None' handle
        // if the operations was successful.

        ///////////////////////////////////////////////////////////////
        // Make Esys create a new ObjectHandle from the
        // data in the TPM.
        //
        // The handle is gone so if this fails it is not
        // possible to remove the defined space.
        let new_nv_index_handle = context
            .tr_from_tpm_public(nv_index_tpm_handle.into())
            .map_err(|e| -> tss_esapi::Result<ObjectHandle> {
                panic!("tr_from_tpm_public failed: {}", e);
            })
            .expect("Error when call tr_from_tpm_public");
        ///////////////////////////////////////////////////////////////
        // Get name of the object using the new handle
        //
        let actual_name = context
            .tr_get_name(new_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, new_nv_index_handle.into(), "tr_get_name"))
            .expect("Failed to call tr_get_name");
        ///////////////////////////////////////////////////////////////
        // Remove undefine the space
        //
        // Set password authorization
        context.set_sessions((Some(AuthSession::Password), None, None));
        context
            .nv_undefine_space(Provision::Owner, new_nv_index_handle.into())
            .expect("Call to nv_undefine_space failed");
        ///////////////////////////////////////////////////////////////
        // Check that we got the correct name
        //
        assert_eq!(expected_name, actual_name);
    }

    #[test]
    fn read_from_retrieved_handle_using_password_authorization() {
        let nv_index_tpm_handle = NvIndexTpmHandle::new(0x01500023).unwrap();

        remove_nv_index_handle_from_tpm(nv_index_tpm_handle, Provision::Owner);

        let mut context = create_ctx_without_session();

        let auth = Auth::try_from(vec![
            10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        ])
        .unwrap();

        // closure for cleaning up if a call fails.
        let cleanup = |context: &mut Context,
                       e: tss_esapi::Error,
                       handle: NvIndexHandle,
                       fn_name: &str|
         -> tss_esapi::Error {
            // Set password authorization
            context.set_sessions((Some(AuthSession::Password), None, None));
            context
                .nv_undefine_space(Provision::Owner, handle)
                .expect("Call to nv_undefine_space failed");
            panic!("{} failed: {}", fn_name, e);
        };

        // Create nv public. Only use auth for write.
        let nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_auth_write(true)
            .with_auth_read(true)
            .build()
            .expect("Failed to create auth nv index attributes");

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index_tpm_handle)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Define space
        //
        // Set password authorization when creating the space.
        context.set_sessions((Some(AuthSession::Password), None, None));
        let initial_nv_index_handle = context
            .nv_define_space(Provision::Owner, Some(auth.clone()), nv_public)
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Read the name from the tpm
        //
        // No password authorization.
        context.clear_sessions();
        let (_expected_nv_public, initial_name) = context
            .nv_read_public(initial_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "nv_read_public"))
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Write data to created index.
        //
        // When the write succeeds the attributes will change
        // and there for the name will change.
        let expected_data = MaxNvBuffer::try_from(vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ])
        .unwrap();
        context.set_sessions((Some(AuthSession::Password), None, None));
        context
            .nv_write(
                NvAuth::NvIndex(initial_nv_index_handle),
                initial_nv_index_handle,
                expected_data.clone(),
                0,
            )
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "nv_write"))
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Read the new name that have been calculated after the write.
        //
        // No password authorization.
        context.clear_sessions();
        let (_expected_nv_public, expected_name) = context
            .nv_read_public(initial_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "nv_read_public"))
            .unwrap();
        assert_ne!(initial_name, expected_name);
        ///////////////////////////////////////////////////////////////
        // Close the esys handle (remove all meta data).
        //
        let mut handle_to_be_closed: ObjectHandle = initial_nv_index_handle.into();
        context
            .tr_close(&mut handle_to_be_closed)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "tr_close"))
            .unwrap();
        assert_eq!(handle_to_be_closed, ObjectHandle::None);
        // The value of the handle_to_be_closed will be set to a 'None' handle
        // if the operations was successful.

        ///////////////////////////////////////////////////////////////
        // Make Esys create a new ObjectHandle from the
        // data in the TPM.
        //
        // The handle is gone so if this fails it is not
        // possible to remove the defined space.
        let new_nv_index_handle = context
            .tr_from_tpm_public(nv_index_tpm_handle.into())
            .map(NvIndexHandle::from)
            .expect("tr_from_tpm_public failed: {}");
        ///////////////////////////////////////////////////////////////
        // Get name of the object using the new handle
        //
        let actual_name = context
            .tr_get_name(new_nv_index_handle.into())
            .map_err(|e| cleanup(&mut context, e, new_nv_index_handle, "tr_get_name"))
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Call nv_read to get data from nv_index.
        //

        // Set authorization for the retrieved handle
        context
            .tr_set_auth(new_nv_index_handle.into(), auth)
            .map_err(|e| cleanup(&mut context, e, new_nv_index_handle, "tr_set_auth"))
            .unwrap();
        // read the data
        context.set_sessions((Some(AuthSession::Password), None, None));
        let actual_data = context
            .nv_read(
                NvAuth::NvIndex(new_nv_index_handle),
                new_nv_index_handle,
                32,
                0,
            )
            .map_err(|e| cleanup(&mut context, e, new_nv_index_handle, "nv_read"))
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Remove undefine the space
        //
        // Set password authorization
        context.set_sessions((Some(AuthSession::Password), None, None));
        context
            .nv_undefine_space(Provision::Owner, new_nv_index_handle)
            .expect("Call to nv_undefine_space failed");
        ///////////////////////////////////////////////////////////////
        // The name will have changed
        //
        assert_eq!(expected_name, actual_name);
        assert_eq!(expected_data, actual_data);
    }
}
