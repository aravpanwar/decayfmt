// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::tss::{TPM2_PERSISTENT_FIRST, TPM2_TRANSIENT_FIRST},
    handles::{PermanentTpmHandle, PersistentTpmHandle, TpmHandle, TransientTpmHandle},
    structures::HandleList,
    tss2_esys::{TPM2_HANDLE, TPML_HANDLE},
    Error, WrapperErrorKind,
};

#[test]
fn test_conversions() {
    let expected_handles: Vec<TpmHandle> = vec![
        PermanentTpmHandle::First.into(),
        (PersistentTpmHandle::try_from(TPM2_PERSISTENT_FIRST).unwrap()).into(),
        (TransientTpmHandle::try_from(TPM2_TRANSIENT_FIRST).unwrap()).into(),
    ];
    let mut handle_list = HandleList::new();
    for handle in expected_handles.iter() {
        handle_list
            .add(*handle)
            .expect("Failed to add handle to list");
    }

    assert_eq!(expected_handles.len(), handle_list.len());

    expected_handles
        .iter()
        .zip(handle_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual,
                "The created handle list did not contain the expected values"
            );
        });

    let tpml_handle = TPML_HANDLE::from(handle_list);
    assert_eq!(
        expected_handles.len(),
        tpml_handle.count as usize,
        "The number of handles in the TPML_HANDLE is different than expected"
    );

    expected_handles
        .iter()
        .zip(tpml_handle.handle[..expected_handles.len()].iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                TPM2_HANDLE::from(*expected),
                *actual,
                "Got mismatch between expected FFI handle and actual handle"
            )
        });

    let handle_list =
        HandleList::try_from(tpml_handle).expect("Failed to convert from TPML_HANDLE");

    assert_eq!(
        expected_handles.len(),
        handle_list.len(),
        "Converted handle list has a different length"
    );

    expected_handles
        .iter()
        .zip(handle_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual,
                "The converted handle list did not contain the expected values"
            );
        });
}

#[test]
fn test_vector_conversion() {
    let expected_handles: Vec<TpmHandle> = vec![
        PermanentTpmHandle::First.into(),
        (PersistentTpmHandle::try_from(TPM2_PERSISTENT_FIRST).unwrap()).into(),
        (TransientTpmHandle::try_from(TPM2_TRANSIENT_FIRST).unwrap()).into(),
    ];

    let handle_list =
        HandleList::try_from(expected_handles.clone()).expect("Failed to convert from vector");

    expected_handles
        .iter()
        .zip(handle_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual,
                "The converted handle list did not contain the expected values"
            );
        });

    let converted_handles = Vec::<TpmHandle>::from(handle_list);

    assert_eq!(
        expected_handles, converted_handles,
        "Converted vector did not match initial vector"
    );
}

#[test]
fn test_add_too_many() {
    let mut handle_list = HandleList::new();
    for _ in 0..HandleList::MAX_SIZE {
        handle_list
            .add(PermanentTpmHandle::First.into())
            .expect("Failed to add the maximum amount of handles");
    }

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::WrongParamSize)),
        handle_list.add(PermanentTpmHandle::First.into()),
        "Added more handles than should've been possible"
    );
}

#[test]
fn test_invalid_size_tpml() {
    let tpml = TPML_HANDLE {
        count: (HandleList::MAX_SIZE + 1) as u32,
        handle: [0; 254],
    };

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        HandleList::try_from(tpml),
        "Converting from TPML_HANDLE did not produce the expected failure"
    );
}

#[test]
fn test_invalid_size_vec() {
    let vec = vec![TpmHandle::Permanent(PermanentTpmHandle::First); HandleList::MAX_SIZE + 1];

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        HandleList::try_from(vec),
        "Converting from vector of handles did not produce the expected failure"
    );
}
