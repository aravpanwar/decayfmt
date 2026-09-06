// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    attributes::{NvIndexAttributes, NvIndexAttributesBuilder},
    constants::NvIndexType,
    Error, WrapperErrorKind,
};

#[test]
fn test_invalid_index_type_value() {
    // 15(1111) - invalid
    let invalid_15 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1111_0000u32);
    let _ = invalid_15.index_type().unwrap_err();

    // 14(1110) - invalid
    let invalid_14 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1110_0000u32);
    let _ = invalid_14.index_type().unwrap_err();

    // 13(1101) - invalid
    let invalid_13 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1101_0000u32);
    let _ = invalid_13.index_type().unwrap_err();

    // 12(1100) - invalid
    let invalid_12 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1100_0000u32);
    let _ = invalid_12.index_type().unwrap_err();

    // 11(1011) - invalid
    let invalid_11 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1011_0000u32);
    let _ = invalid_11.index_type().unwrap_err();

    // 10(1010) - invalid
    let invalid_10 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1011_0000u32);
    let _ = invalid_10.index_type().unwrap_err();

    // 9(1001) - Valid

    // 8(1000) - Valid

    // 7(0111) - invalid
    let invalid_7 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_0111_0000u32);
    let _ = invalid_7.index_type().unwrap_err();

    // 6(0110) - invalid
    let invalid_6 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_0110_0000u32);
    let _ = invalid_6.index_type().unwrap_err();

    // 5(0101) - invalid
    let invalid_5 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_0101_0000u32);
    let _ = invalid_5.index_type().unwrap_err();

    // 4(0100) - valid

    // 3(0011) - invalid
    let invalid_3 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_0011_0000u32);
    let _ = invalid_3.index_type().unwrap_err();

    // 2(0010) - valid

    // 1(0001) - valid

    // 0(0000) - valid
}

macro_rules! single_attribute_error {
    ($method:ident) => {
        assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::ParamsMissing)),
            NvIndexAttributesBuilder::new().$method(true).build()
        );
    };
}

#[test]
fn test_nv_index_attributes_builder_missing_read_attribute_failure() {
    // Test missing read error

    // Building with only PP write set this should result in an error
    single_attribute_error!(with_pp_write);
    // Building with only owner write set this should result in an error
    single_attribute_error!(with_owner_write);
    // Building with only auth write set this should result in an error
    single_attribute_error!(with_auth_write);
    // Building with only policy write set this should result in an error
    single_attribute_error!(with_policy_write);
    // Building with all of them set still results in an error
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::ParamsMissing)),
        NvIndexAttributesBuilder::new()
            .with_pp_write(true)
            .with_owner_write(true)
            .with_auth_write(true)
            .with_policy_write(true)
            .build()
    );
}

#[test]
fn test_nv_index_attributes_builder_missing_write_attribute_failure() {
    // Test missing write error

    // Building with only PP read set this should result in an error
    single_attribute_error!(with_pp_read);
    // Building with only owner read set this should result in an error
    single_attribute_error!(with_owner_read);
    // Building with only auth read set this should result in an error
    single_attribute_error!(with_auth_read);
    // Building with only policy read set this should result in an error
    single_attribute_error!(with_policy_read);
    // Building with all of them set still results in an error
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::ParamsMissing)),
        NvIndexAttributesBuilder::new()
            .with_pp_read(true)
            .with_owner_read(true)
            .with_auth_read(true)
            .with_policy_read(true)
            .build()
    );
}

#[test]
fn test_nv_index_attributes_builder_missing_no_da_attribute_with_pin_fail_index_type() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::ParamsMissing)),
        NvIndexAttributesBuilder::new()
            .with_nv_index_type(NvIndexType::PinFail)
            .build()
    );
}

#[test]
fn test_attributes_builder() {
    let mut builder = NvIndexAttributesBuilder::new();

    // Need to set a read and write in order to be able to build.
    builder = builder.with_pp_write(true).with_pp_read(true);
    assert_eq!(
        0b0000_0000_0000_0001_0000_0000_0000_0001u32,
        builder
            .build()
            .expect("Failed to build with pp_write and pp_read added")
            .0
    );

    builder = builder.with_owner_write(true);
    assert_eq!(
        0b0000_0000_0000_0001_0000_0000_0000_0011u32,
        builder
            .build()
            .expect("Failed to build with owner_write added")
            .0
    );

    builder = builder.with_auth_write(true);
    assert_eq!(
        0b0000_0000_0000_0001_0000_0000_0000_0111u32,
        builder
            .build()
            .expect("Failed to build with auth_write added")
            .0
    );

    builder = builder.with_policy_write(true);
    assert_eq!(
        0b0000_0000_0000_0001_0000_0000_0000_1111u32,
        builder
            .build()
            .expect("Failed to build with policy_write added")
            .0
    );

    {
        // PinPass = 1001 (7,4)
        builder = builder.with_nv_index_type(NvIndexType::PinPass);
        let attributes = builder
            .build()
            .expect("Failed to build with nv index type PinPass added");
        assert_eq!(0b0000_0000_0000_0001_0000_0000_1001_1111u32, attributes.0);
        assert_eq!(NvIndexType::PinPass, attributes.index_type().unwrap());
    }

    // (8,9 Reserved)
    builder = builder.with_policy_delete(true);
    assert_eq!(
        0b0000_0000_0000_0001_0000_0100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with policy_delete added")
            .0
    );

    builder = builder.with_write_locked(true);
    assert_eq!(
        0b0000_0000_0000_0001_0000_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with write_locked added")
            .0
    );

    builder = builder.with_write_all(true);
    assert_eq!(
        0b0000_0000_0000_0001_0001_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with write_all added")
            .0
    );

    builder = builder.with_write_define(true);
    assert_eq!(
        0b0000_0000_0000_0001_0011_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with write_define added")
            .0
    );

    builder = builder.with_write_stclear(true);
    assert_eq!(
        0b0000_0000_0000_0001_0111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with write_stclear added")
            .0
    );

    builder = builder.with_global_lock(true);
    assert_eq!(
        0b0000_0000_0000_0001_1111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with global_lock added")
            .0
    );

    builder = builder.with_owner_read(true);
    assert_eq!(
        0b0000_0000_0000_0011_1111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with owner_read added")
            .0
    );

    builder = builder.with_auth_read(true);
    assert_eq!(
        0b0000_0000_0000_0111_1111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with auth_read added")
            .0
    );

    builder = builder.with_policy_read(true);
    assert_eq!(
        0b0000_0000_0000_1111_1111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with policy_read added")
            .0
    );

    // Reserved (24, 20)
    builder = builder.with_no_da(true);
    assert_eq!(
        0b0000_0010_0000_1111_1111_1100_1001_1111u32,
        builder.build().expect("Failed to build with no_da added").0
    );

    builder = builder.with_orderly(true);
    assert_eq!(
        0b0000_0110_0000_1111_1111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with oderly added")
            .0
    );

    builder = builder.with_clear_stclear(true);
    assert_eq!(
        0b0000_1110_0000_1111_1111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with clear_stclear added")
            .0
    );

    builder = builder.with_read_locked(true);
    assert_eq!(
        0b0001_1110_0000_1111_1111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with read_locked added")
            .0
    );

    builder = builder.with_written(true);
    assert_eq!(
        0b0011_1110_0000_1111_1111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with written added")
            .0
    );

    builder = builder.with_platform_create(true);
    assert_eq!(
        0b0111_1110_0000_1111_1111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with platform_create added")
            .0
    );

    builder = builder.with_read_stclear(true);
    assert_eq!(
        0b1111_1110_0000_1111_1111_1100_1001_1111u32,
        builder
            .build()
            .expect("Failed to build with read_stclear added")
            .0
    );
}
