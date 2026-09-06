// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::{
    convert::TryFrom,
    io::{ErrorKind, Seek, SeekFrom, Write},
};
use tss_esapi::{
    abstraction::nv,
    attributes::NvIndexAttributesBuilder,
    handles::{NvIndexHandle, NvIndexTpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        resource_handles::{NvAuth, Provision},
    },
    structures::{MaxNvBuffer, NvPublicBuilder},
    Context,
};

use crate::common::create_ctx_with_session;

fn write_nv_index(context: &mut Context, nv_index: NvIndexTpmHandle) -> NvIndexHandle {
    // Create owner nv public.
    let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
        .with_owner_write(true)
        .with_owner_read(true)
        .with_pp_read(true)
        .with_owner_read(true)
        .build()
        .expect("Failed to create owner nv index attributes");

    let owner_nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(owner_nv_index_attributes)
        .with_data_area_size(1540)
        .build()
        .unwrap();

    let owner_nv_index_handle = context
        .nv_define_space(Provision::Owner, None, owner_nv_public)
        .unwrap();

    let value = [1, 2, 3, 4, 5, 6, 7];
    let expected_data = MaxNvBuffer::try_from(value.to_vec()).unwrap();

    // Write the data using Owner authorization
    context
        .nv_write(
            NvAuth::Owner,
            owner_nv_index_handle,
            expected_data.clone(),
            0,
        )
        .unwrap();
    context
        .nv_write(NvAuth::Owner, owner_nv_index_handle, expected_data, 1024)
        .unwrap();

    owner_nv_index_handle
}

#[test]
fn list() {
    let mut context = create_ctx_with_session();

    let nv_index = NvIndexTpmHandle::new(0x01500015).unwrap();

    assert!(!nv::list(&mut context)
        .unwrap()
        .iter()
        .map(|(public, _)| public.nv_index())
        .any(|x| x == nv_index));

    let owner_nv_index_handle = write_nv_index(&mut context, nv_index);

    assert!(nv::list(&mut context)
        .unwrap()
        .iter()
        .map(|(public, _)| public.nv_index())
        .any(|x| x == nv_index));

    // Need to get the ESYS handle again, as it was closed by nv::list above
    let owner_nv_index_handle = context
        .tr_from_tpm_public(nv_index.into())
        .unwrap_or_else(|_| owner_nv_index_handle.into());
    context
        .nv_undefine_space(Provision::Owner, owner_nv_index_handle.into())
        .expect("Call to nv_undefine_space failed");
}

#[test]
fn read_full() {
    let mut context = create_ctx_with_session();

    let nv_index = NvIndexTpmHandle::new(0x01500015).unwrap();

    let owner_nv_index_handle = write_nv_index(&mut context, nv_index);

    // Now read it back
    let read_result = nv::read_full(&mut context, NvAuth::Owner, nv_index);

    // Need to get the ESYS handle again, as it was closed by nv::read_full above
    let owner_nv_index_handle = context
        .tr_from_tpm_public(nv_index.into())
        .unwrap_or_else(|_| owner_nv_index_handle.into());
    context
        .nv_undefine_space(Provision::Owner, owner_nv_index_handle.into())
        .expect("Call to nv_undefine_space failed");

    let read_result = read_result.unwrap();
    assert_eq!(read_result.len(), 1540);
    assert_eq!(read_result[0..7], [1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(read_result[1024..1031], [1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn write() {
    let mut context = create_ctx_with_session();

    let nv_index = NvIndexTpmHandle::new(0x01500015).unwrap();

    let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
        .with_owner_write(true)
        .with_owner_read(true)
        .with_pp_read(true)
        .build()
        .expect("Failed to create owner nv index attributes");
    let owner_nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(owner_nv_index_attributes)
        .with_data_area_size(1540)
        .build()
        .unwrap();

    let mut rw = nv::NvOpenOptions::NewIndex {
        nv_public: owner_nv_public,
        auth_handle: NvAuth::Owner,
    }
    .open(&mut context)
    .unwrap();

    let value = [1, 2, 3, 4, 5, 6, 7];
    rw.write_all(&value).unwrap();
    rw.seek(SeekFrom::Start(1024)).unwrap();
    rw.write_all(&value).unwrap();

    rw.seek(SeekFrom::Start(1540)).unwrap();
    let e = rw.write_all(&value).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::WriteZero);

    // Drop the reader/writer so we can use context again
    drop(rw);

    // Now read it back
    let read_result = nv::read_full(&mut context, NvAuth::Owner, nv_index).unwrap();

    assert_eq!(read_result.len(), 1540);
    assert_eq!(read_result[0..7], [1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(read_result[1024..1031], [1, 2, 3, 4, 5, 6, 7]);

    let owner_nv_index_handle = context
        .execute_without_session(|ctx| ctx.tr_from_tpm_public(nv_index.into()))
        .expect("Call to tr_from_tpm_public failed");
    context
        .nv_undefine_space(Provision::Owner, owner_nv_index_handle.into())
        .expect("Call to nv_undefine_space failed");
}
