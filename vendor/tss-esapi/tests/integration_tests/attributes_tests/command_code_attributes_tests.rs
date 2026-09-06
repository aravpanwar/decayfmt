// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use bitfield::bitfield;
use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    attributes::CommandCodeAttributes, constants::CommandCode, tss2_esys::TPMA_CC, Error,
    WrapperErrorKind,
};

bitfield! {
    #[derive(Copy, Clone, Eq, PartialEq)]
    struct ExpectedAttributes(TPMA_CC);
    impl Debug;
    u16, command_index, set_command_index: 15, 0;
    u8, reserved, set_reserved: 21, 16;
    nv, set_nv: 22;
    extensive, set_extensive: 23;
    flushed, set_flushed: 24;
    u8, c_handles, set_c_handles: 27, 25;
    r_handle, set_r_handle: 28;
    is_vendor_specific, set_vendor_specific: 29;
    u8, res, set_res: 31, 30; // shall be zero
}

#[test]
fn test_conversions_non_vendor_specific() {
    let expected = {
        let mut ea = ExpectedAttributes(0);
        ea.set_vendor_specific(false);
        // Because it is not vendor specific it needs the
        // command index needs to be set to a value present
        // in CommandCodes.
        ea.set_command_index(
            u32::from(CommandCode::AcGetCapability)
                .try_into()
                .expect("Failed to convert CommandCode to an u16 command code index value"),
        );
        ea.set_nv(true);
        ea.set_extensive(true);
        ea.set_flushed(true);
        ea.set_c_handles(6);
        ea.set_r_handle(true);
        ea
    };

    let command_code_attributes: CommandCodeAttributes = expected
        .0
        .try_into()
        .expect("Failed to convert TPMA_CC to CommandCodeAttributes");

    assert_eq!(
        expected.command_index(),
        command_code_attributes.command_index(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for command index"
    );

    assert_eq!(
        expected.nv(),
        command_code_attributes.nv(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for NV"
    );

    assert_eq!(
        expected.extensive(),
        command_code_attributes.extensive(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for Extensive"
    );

    assert_eq!(
        expected.flushed(),
        command_code_attributes.flushed(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for Flushed"
    );

    assert_eq!(
        expected.c_handles(),
        command_code_attributes.c_handles(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for CHandles"
    );

    assert_eq!(
        expected.r_handle(),
        command_code_attributes.r_handle(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for RHandle"
    );

    assert_eq!(
        expected.is_vendor_specific(),
        command_code_attributes.is_vendor_specific(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for Vendor Specific(V)"
    );

    assert_eq!(
        expected.0,
        command_code_attributes.into(),
        "CommandCodeAttributes did not convert into the expected TPMA_CC value"
    );
}

#[test]
fn test_conversions_vendor_specific() {
    let expected = {
        let mut ea = ExpectedAttributes(0);
        ea.set_vendor_specific(true);
        // Vendor specific is set to true so any
        // u16 value is valid.
        ea.set_command_index(0xFFFFu16);
        ea.set_nv(true);
        ea.set_extensive(true);
        ea.set_flushed(true);
        ea.set_c_handles(6);
        ea.set_r_handle(true);
        ea
    };

    let command_code_attributes: CommandCodeAttributes = expected
        .0
        .try_into()
        .expect("Failed to convert TPMA_CC to CommandCodeAttributes");

    assert_eq!(
        expected.command_index(),
        command_code_attributes.command_index(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for command index"
    );

    assert_eq!(
        expected.nv(),
        command_code_attributes.nv(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for NV"
    );

    assert_eq!(
        expected.extensive(),
        command_code_attributes.extensive(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for Extensive"
    );

    assert_eq!(
        expected.flushed(),
        command_code_attributes.flushed(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for Flushed"
    );

    assert_eq!(
        expected.c_handles(),
        command_code_attributes.c_handles(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for CHandles"
    );

    assert_eq!(
        expected.r_handle(),
        command_code_attributes.r_handle(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for RHandle"
    );

    assert_eq!(
        expected.is_vendor_specific(),
        command_code_attributes.is_vendor_specific(),
        "CommandCodeAttributes converted from TPMA_CC did not contain the expected value for Vendor Specific(V)"
    );

    assert_eq!(
        expected.0,
        command_code_attributes.into(),
        "CommandCodeAttributes did not convert into the expected TPMA_CC value"
    );
}

#[test]
fn test_invalid_conversions_non_vendor_specific_invalid_command_index() {
    let invalid_tpma_cc = {
        let mut ea = ExpectedAttributes(0);
        ea.set_vendor_specific(false);
        // Vendor specific is set to false and
        // 0xFFFFu16 does not correspond to any
        // CommandCode so this will be invalid.
        ea.set_command_index(0xFFFFu16);
        ea.set_nv(true);
        ea.set_extensive(true);
        ea.set_flushed(true);
        ea.set_c_handles(6);
        ea.set_r_handle(true);
        ea.0
    };

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        CommandCodeAttributes::try_from(invalid_tpma_cc),
        "Converting TPMA_CC witrh invalid command code index into CommandCodeAttributes did no produce the expected error"
    );
}

#[test]
fn test_invalid_conversions_with_reserve_bits_set() {
    let invalid_tpma_cc_with_set_reserve_bits = {
        let mut ea = ExpectedAttributes(0);
        ea.set_reserved(2); // Specification says the reserved bits 21:16 shall be zero so this will be invalid.
        ea.set_vendor_specific(true);
        // Vendor specific is set to true so any
        // u16 value is valid.
        ea.set_command_index(0xFFFFu16);
        ea.set_nv(true);
        ea.set_extensive(true);
        ea.set_flushed(true);
        ea.set_c_handles(6);
        ea.set_r_handle(true);
        ea.0
    };

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        CommandCodeAttributes::try_from(invalid_tpma_cc_with_set_reserve_bits),
        "Converting TPMA_CC with reserved bits 21:16 set into CommandCodeAttributes did no produce the expected error"
    );

    let invalid_tpma_cc_with_set_res_bits = {
        let mut ea = ExpectedAttributes(0);
        ea.set_vendor_specific(true);
        // Vendor specific is set to true so any
        // u16 value is valid.
        ea.set_command_index(0xFFFFu16);
        ea.set_nv(true);
        ea.set_extensive(true);
        ea.set_flushed(true);
        ea.set_c_handles(6);
        ea.set_r_handle(true);
        ea.set_res(1); // Speacification says res bits 31:30 shall be zero so this will be invalid.
        ea.0
    };

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        CommandCodeAttributes::try_from(invalid_tpma_cc_with_set_res_bits),
        "Converting TPMA_CC with reserved bits 31:30 set into CommandCodeAttributes did no produce the expected error"
    );
}

#[test]
fn test_builder() {
    let expected = {
        let mut ea = ExpectedAttributes(0);
        ea.set_vendor_specific(true);
        // Vendor specific is set to true so any
        // u16 value is valid.
        ea.set_command_index(0xFFFFu16);
        ea.set_nv(true);
        ea.set_extensive(true);
        ea.set_flushed(true);
        ea.set_c_handles(6);
        ea.set_r_handle(true);
        ea
    };

    let actual = CommandCodeAttributes::builder()
        .with_vendor_specific(expected.is_vendor_specific())
        .with_command_index(expected.command_index())
        .with_nv(expected.nv())
        .with_extensive(expected.extensive())
        .with_flushed(expected.flushed())
        .with_c_handles(expected.c_handles())
        .with_r_handle(expected.r_handle())
        .build()
        .expect("Failed to buiild command code attributes");

    assert_eq!(
        expected.command_index(),
        actual.command_index(),
        "Command index value mismatch between expected and attributes built with builder"
    );

    assert_eq!(
        expected.nv(),
        actual.nv(),
        "Nv value mismatch between expected and attributes built with builder"
    );

    assert_eq!(
        expected.extensive(),
        actual.extensive(),
        "Extensive value mismatch between expected and attributes built with builder"
    );

    assert_eq!(
        expected.flushed(),
        actual.flushed(),
        "Flushed value mismatch between expected and attributes built with builder"
    );

    assert_eq!(
        expected.c_handles(),
        actual.c_handles(),
        "C Handles value mismatch between expected and attributes built with builder"
    );

    assert_eq!(
        expected.r_handle(),
        actual.r_handle(),
        "R Handle value mismatch between expected and attributes built with builder"
    );

    assert_eq!(
        expected.is_vendor_specific(),
        actual.is_vendor_specific(),
        "Vendor specific (V) value mismatch between expected and attributes built with builder"
    );

    assert_eq!(
            expected.0,
            actual.into(),
            "CommandCodeAttributes built using the builder did not convert into the expected TPMA_CC value"
    );
}

#[test]
fn test_builder_errors() {
    let expected_result = Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
    let actual_result = CommandCodeAttributes::builder()
        .with_vendor_specific(false) // Vendor specific is false so the value must be a command code
        .with_command_index(0xFFFFu16) // This is not a command code so this should make the build fail.
        .with_nv(true)
        .with_extensive(true)
        .with_flushed(true)
        .with_c_handles(6)
        .with_r_handle(true)
        .build();

    assert_eq!(
        expected_result, actual_result,
        "Building command code arguments with bad combination of vendor specific and command index did not produce the expected error",
    );
}
