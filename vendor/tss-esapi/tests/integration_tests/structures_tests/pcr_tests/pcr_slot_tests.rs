// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{structures::PcrSlot, tss2_esys::TPM2_PCR_SELECT_MAX, Error, WrapperErrorKind};

#[test]
fn test_conversion_to_u32() {
    assert_eq!(0x0000_0001u32, PcrSlot::Slot0.into());
    assert_eq!(0x0000_0002u32, PcrSlot::Slot1.into());
    assert_eq!(0x0000_0004u32, PcrSlot::Slot2.into());
    assert_eq!(0x0000_0008u32, PcrSlot::Slot3.into());
    assert_eq!(0x0000_0010u32, PcrSlot::Slot4.into());
    assert_eq!(0x0000_0020u32, PcrSlot::Slot5.into());
    assert_eq!(0x0000_0040u32, PcrSlot::Slot6.into());
    assert_eq!(0x0000_0080u32, PcrSlot::Slot7.into());

    assert_eq!(0x0000_0100u32, PcrSlot::Slot8.into());
    assert_eq!(0x0000_0200u32, PcrSlot::Slot9.into());
    assert_eq!(0x0000_0400u32, PcrSlot::Slot10.into());
    assert_eq!(0x0000_0800u32, PcrSlot::Slot11.into());
    assert_eq!(0x0000_1000u32, PcrSlot::Slot12.into());
    assert_eq!(0x0000_2000u32, PcrSlot::Slot13.into());
    assert_eq!(0x0000_4000u32, PcrSlot::Slot14.into());
    assert_eq!(0x0000_8000u32, PcrSlot::Slot15.into());

    assert_eq!(0x0001_0000u32, PcrSlot::Slot16.into());
    assert_eq!(0x0002_0000u32, PcrSlot::Slot17.into());
    assert_eq!(0x0004_0000u32, PcrSlot::Slot18.into());
    assert_eq!(0x0008_0000u32, PcrSlot::Slot19.into());
    assert_eq!(0x0010_0000u32, PcrSlot::Slot20.into());
    assert_eq!(0x0020_0000u32, PcrSlot::Slot21.into());
    assert_eq!(0x0040_0000u32, PcrSlot::Slot22.into());
    assert_eq!(0x0080_0000u32, PcrSlot::Slot23.into());
}
macro_rules! convert_from_u32_test {
    ($value:expr, $slot_number:path) => {
        assert_eq!(
            PcrSlot::try_from($value).expect(&format!(
                "Failed to convert {} to {}",
                $value,
                stringify!($slot_number)
            )),
            $slot_number,
        );
    };
}

#[test]
fn test_conversion_from_u32() {
    convert_from_u32_test!(0x0000_0001u32, PcrSlot::Slot0);
    convert_from_u32_test!(0x0000_0002u32, PcrSlot::Slot1);
    convert_from_u32_test!(0x0000_0004u32, PcrSlot::Slot2);
    convert_from_u32_test!(0x0000_0008u32, PcrSlot::Slot3);
    convert_from_u32_test!(0x0000_0010u32, PcrSlot::Slot4);
    convert_from_u32_test!(0x0000_0020u32, PcrSlot::Slot5);
    convert_from_u32_test!(0x0000_0040u32, PcrSlot::Slot6);
    convert_from_u32_test!(0x0000_0080u32, PcrSlot::Slot7);

    convert_from_u32_test!(0x0000_0100u32, PcrSlot::Slot8);
    convert_from_u32_test!(0x0000_0200u32, PcrSlot::Slot9);
    convert_from_u32_test!(0x0000_0400u32, PcrSlot::Slot10);
    convert_from_u32_test!(0x0000_0800u32, PcrSlot::Slot11);
    convert_from_u32_test!(0x0000_1000u32, PcrSlot::Slot12);
    convert_from_u32_test!(0x0000_2000u32, PcrSlot::Slot13);
    convert_from_u32_test!(0x0000_4000u32, PcrSlot::Slot14);
    convert_from_u32_test!(0x0000_8000u32, PcrSlot::Slot15);

    convert_from_u32_test!(0x0001_0000u32, PcrSlot::Slot16);
    convert_from_u32_test!(0x0002_0000u32, PcrSlot::Slot17);
    convert_from_u32_test!(0x0004_0000u32, PcrSlot::Slot18);
    convert_from_u32_test!(0x0008_0000u32, PcrSlot::Slot19);
    convert_from_u32_test!(0x0010_0000u32, PcrSlot::Slot20);
    convert_from_u32_test!(0x0020_0000u32, PcrSlot::Slot21);
    convert_from_u32_test!(0x0040_0000u32, PcrSlot::Slot22);
    convert_from_u32_test!(0x0080_0000u32, PcrSlot::Slot23);
}

#[test]
fn test_conversion_from_u32_errors() {
    assert_eq!(
        PcrSlot::try_from(0u32),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
    );
    assert_eq!(
        PcrSlot::try_from(1234u32),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
    );
}

macro_rules! convert_to_tss_type_test {
    ($value:expr, $slot_number:path) => {
        let expected: [u8; TPM2_PCR_SELECT_MAX as usize] = $value.to_le_bytes();
        let actual: [u8; TPM2_PCR_SELECT_MAX as usize] = $slot_number.into();
        assert_eq!(expected, actual);
    };
}

#[test]
fn test_conversion_to_tss_type() {
    convert_to_tss_type_test!(0x0000_0001u32, PcrSlot::Slot0);
    convert_to_tss_type_test!(0x0000_0002u32, PcrSlot::Slot1);
    convert_to_tss_type_test!(0x0000_0004u32, PcrSlot::Slot2);
    convert_to_tss_type_test!(0x0000_0008u32, PcrSlot::Slot3);
    convert_to_tss_type_test!(0x0000_0010u32, PcrSlot::Slot4);
    convert_to_tss_type_test!(0x0000_0020u32, PcrSlot::Slot5);
    convert_to_tss_type_test!(0x0000_0040u32, PcrSlot::Slot6);
    convert_to_tss_type_test!(0x0000_0080u32, PcrSlot::Slot7);

    convert_to_tss_type_test!(0x0000_0100u32, PcrSlot::Slot8);
    convert_to_tss_type_test!(0x0000_0200u32, PcrSlot::Slot9);
    convert_to_tss_type_test!(0x0000_0400u32, PcrSlot::Slot10);
    convert_to_tss_type_test!(0x0000_0800u32, PcrSlot::Slot11);
    convert_to_tss_type_test!(0x0000_1000u32, PcrSlot::Slot12);
    convert_to_tss_type_test!(0x0000_2000u32, PcrSlot::Slot13);
    convert_to_tss_type_test!(0x0000_4000u32, PcrSlot::Slot14);
    convert_to_tss_type_test!(0x0000_8000u32, PcrSlot::Slot15);

    convert_to_tss_type_test!(0x0001_0000u32, PcrSlot::Slot16);
    convert_to_tss_type_test!(0x0002_0000u32, PcrSlot::Slot17);
    convert_to_tss_type_test!(0x0004_0000u32, PcrSlot::Slot18);
    convert_to_tss_type_test!(0x0008_0000u32, PcrSlot::Slot19);
    convert_to_tss_type_test!(0x0010_0000u32, PcrSlot::Slot20);
    convert_to_tss_type_test!(0x0020_0000u32, PcrSlot::Slot21);
    convert_to_tss_type_test!(0x0040_0000u32, PcrSlot::Slot22);
    convert_to_tss_type_test!(0x0080_0000u32, PcrSlot::Slot23);
}

macro_rules! convert_from_tss_type_test {
    ($value:expr, $slot_number:path) => {
        assert_eq!(
            PcrSlot::try_from($value).expect(&format!("TSS data to {}", stringify!($slot_number))),
            $slot_number,
        );
    };
}

#[test]
fn test_conversion_from_tss_type() {
    convert_from_tss_type_test!([1u8, 0u8, 0u8, 0u8], PcrSlot::Slot0);
    convert_from_tss_type_test!([2u8, 0u8, 0u8, 0u8], PcrSlot::Slot1);
    convert_from_tss_type_test!([4u8, 0u8, 0u8, 0u8], PcrSlot::Slot2);
    convert_from_tss_type_test!([8u8, 0u8, 0u8, 0u8], PcrSlot::Slot3);
    convert_from_tss_type_test!([16u8, 0u8, 0u8, 0u8], PcrSlot::Slot4);
    convert_from_tss_type_test!([32u8, 0u8, 0u8, 0u8], PcrSlot::Slot5);
    convert_from_tss_type_test!([64u8, 0u8, 0u8, 0u8], PcrSlot::Slot6);
    convert_from_tss_type_test!([128u8, 0u8, 0u8, 0u8], PcrSlot::Slot7);

    convert_from_tss_type_test!([0u8, 1u8, 0u8, 0u8], PcrSlot::Slot8);
    convert_from_tss_type_test!([0u8, 2u8, 0u8, 0u8], PcrSlot::Slot9);
    convert_from_tss_type_test!([0u8, 4u8, 0u8, 0u8], PcrSlot::Slot10);
    convert_from_tss_type_test!([0u8, 8u8, 0u8, 0u8], PcrSlot::Slot11);
    convert_from_tss_type_test!([0u8, 16u8, 0u8, 0u8], PcrSlot::Slot12);
    convert_from_tss_type_test!([0u8, 32u8, 0u8, 0u8], PcrSlot::Slot13);
    convert_from_tss_type_test!([0u8, 64u8, 0u8, 0u8], PcrSlot::Slot14);
    convert_from_tss_type_test!([0u8, 128u8, 0u8, 0u8], PcrSlot::Slot15);

    convert_from_tss_type_test!([0u8, 0u8, 1u8, 0u8], PcrSlot::Slot16);
    convert_from_tss_type_test!([0u8, 0u8, 2u8, 0u8], PcrSlot::Slot17);
    convert_from_tss_type_test!([0u8, 0u8, 4u8, 0u8], PcrSlot::Slot18);
    convert_from_tss_type_test!([0u8, 0u8, 8u8, 0u8], PcrSlot::Slot19);
    convert_from_tss_type_test!([0u8, 0u8, 16u8, 0u8], PcrSlot::Slot20);
    convert_from_tss_type_test!([0u8, 0u8, 32u8, 0u8], PcrSlot::Slot21);
    convert_from_tss_type_test!([0u8, 0u8, 64u8, 0u8], PcrSlot::Slot22);
    convert_from_tss_type_test!([0u8, 0u8, 128u8, 0u8], PcrSlot::Slot23);
}
