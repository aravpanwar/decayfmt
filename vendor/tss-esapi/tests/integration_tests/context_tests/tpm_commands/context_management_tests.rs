// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_ctx_save {
    use crate::common::{create_ctx_with_session, decryption_key_pub, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::resource_handles::Hierarchy, structures::Auth};

    #[test]
    fn test_ctx_save() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();
        let key_auth = Auth::try_from(random_digest).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;
        let _ = context.context_save(key_handle.into()).unwrap();
    }

    #[test]
    fn test_ctx_save_leaf() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();
        let key_auth = Auth::try_from(random_digest).unwrap();

        let prim_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                Some(key_auth.clone()),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let result = context
            .create(
                prim_key_handle,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap();

        let key_handle = context
            .load(prim_key_handle, result.out_private, result.out_public)
            .unwrap();
        context.flush_context(prim_key_handle.into()).unwrap();
        let _ = context.context_save(key_handle.into()).unwrap();
    }
}

mod test_ctx_load {
    use crate::common::{create_ctx_with_session, decryption_key_pub, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{
        handles::KeyHandle, interface_types::resource_handles::Hierarchy, structures::Auth,
    };

    #[test]
    fn test_ctx_load() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();

        let prim_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                Some(Auth::try_from(random_digest.clone()).unwrap()),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let result = context
            .create(
                prim_key_handle,
                signing_key_pub(),
                Some(Auth::try_from(random_digest).unwrap()),
                None,
                None,
                None,
            )
            .unwrap();

        let key_handle = context
            .load(prim_key_handle, result.out_private, result.out_public)
            .unwrap();
        context.flush_context(prim_key_handle.into()).unwrap();
        let key_ctx = context.context_save(key_handle.into()).unwrap();
        let key_handle = context.context_load(key_ctx).map(KeyHandle::from).unwrap();
        let _ = context.read_public(key_handle).unwrap();
    }
}

mod test_flush_context {
    use crate::common::{create_ctx_with_session, decryption_key_pub, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::resource_handles::Hierarchy, structures::Auth};

    #[test]
    fn test_flush_ctx() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();
        let key_auth = Auth::try_from(random_digest).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;
        context.flush_context(key_handle.into()).unwrap();
        assert!(context.read_public(key_handle).is_err());
    }

    #[test]
    fn test_flush_parent_ctx() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::fill(&mut random_digest).unwrap();
        let key_auth = Auth::try_from(random_digest).unwrap();

        let prim_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                Some(key_auth.clone()),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let result = context
            .create(
                prim_key_handle,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap();

        let key_handle = context
            .load(prim_key_handle, result.out_private, result.out_public)
            .unwrap();
        context.flush_context(prim_key_handle.into()).unwrap();
        let _ = context.read_public(key_handle).unwrap();
    }
}

mod test_evict_control {
    use crate::common::{create_ctx_without_session, decryption_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{
        constants::{tss::TPM2_PERSISTENT_FIRST, CapabilityType},
        handles::{ObjectHandle, PersistentTpmHandle, TpmHandle},
        interface_types::{
            dynamic_handles::Persistent,
            resource_handles::{Hierarchy, Provision},
            session_handles::AuthSession,
        },
        structures::{Auth, CapabilityData},
        tss2_esys::TPM2_HANDLE,
    };

    fn remove_persitent_handle(persistent_tpm_handle: PersistentTpmHandle) {
        let mut context = create_ctx_without_session();
        let mut property = TPM2_PERSISTENT_FIRST;
        while let Ok((capability_data, more_data_available)) =
            context.get_capability(CapabilityType::Handles, property, 1)
        {
            if let CapabilityData::Handles(persistent_handles) = capability_data {
                if let Some(&retrieved_persistent_handle) = persistent_handles.first() {
                    if retrieved_persistent_handle == persistent_tpm_handle.into() {
                        let handle = context
                            .tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
                            .expect("Failed to retrieve handle from TPM");
                        context
                            .evict_control(
                                Provision::Owner,
                                handle,
                                Persistent::Persistent(persistent_tpm_handle),
                            )
                            .expect("Failed to evict persistent handle");
                        return;
                    }

                    if more_data_available {
                        property = TPM2_HANDLE::from(retrieved_persistent_handle) + 1;
                    }
                }
            }

            if !more_data_available {
                return;
            }
        }
    }

    #[test]
    fn test_basic_evict_control() {
        // Create persistent TPM handle with
        let persistent_tpm_handle =
            PersistentTpmHandle::new(u32::from_be_bytes([0x81, 0x00, 0x00, 0x01]))
                .expect("Failed to create persitent tpm handle");
        // Create interface type Persistent by using the handle.
        let persistent = Persistent::Persistent(persistent_tpm_handle);

        // Make sure the handle is not already persistent
        remove_persitent_handle(persistent_tpm_handle);

        // Create context
        let mut context = create_ctx_without_session();

        // Set Password session
        context.set_sessions((Some(AuthSession::Password), None, None));

        // Create primary key handle
        let auth_value_primary = Auth::try_from(vec![1, 2, 3, 4, 5])
            .expect("Failed to crate auth value for primary key");
        let primary_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                Some(auth_value_primary),
                None,
                None,
                None,
            )
            .expect("Failed to create primary key")
            .key_handle;

        // Evict control to make primary_key_handle persistent
        let mut persistent_primary_key_handle = context
            .evict_control(Provision::Owner, primary_key_handle.into(), persistent)
            .expect("Failed to make the primary key handle persistent");

        assert_ne!(persistent_primary_key_handle, ObjectHandle::Null);
        assert_ne!(persistent_primary_key_handle, ObjectHandle::None);

        // Flush out the primary_key_handle
        context
            .flush_context(ObjectHandle::from(primary_key_handle))
            .expect("Failed to flush context");
        // Close the persistent_handle returned by evict_control
        context
            .tr_close(&mut persistent_primary_key_handle)
            .expect("Failed to close persistent handle");

        // Retrieve the handle from the tpm again.
        let retrieved_persistent_handle = context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
                .expect("Failed to load the persistent handle")
        });

        // Evict the persitent handle from the tpm
        context
            .evict_control(Provision::Owner, retrieved_persistent_handle, persistent)
            .expect("Failed to evict persistent handle");

        context.clear_sessions();

        assert_ne!(retrieved_persistent_handle, ObjectHandle::None);
    }
}
