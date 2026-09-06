// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    constants::CommandCode,
    structures::CommandCodeList,
    tss2_esys::{TPM2_CC, TPML_CC},
    Error, WrapperErrorKind,
};

use std::convert::{TryFrom, TryInto};

#[test]
fn test_conversions() {
    let expected_command_codes = [
        CommandCode::ChangeEps,
        CommandCode::ChangePps,
        CommandCode::Clear,
    ];
    let mut command_code_list = CommandCodeList::new();
    for command_code in expected_command_codes.iter() {
        command_code_list
            .add(*command_code)
            .expect("Failed to add command code to command code list");
    }

    assert_eq!(
        expected_command_codes.len(),
        command_code_list.len(),
        "The created command code list did not contain the expected number of elements"
    );

    expected_command_codes
        .iter()
        .zip(command_code_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual,
                "The created command code list did not contain the expected value"
            )
        });

    let tpml_cc: TPML_CC = command_code_list.into();

    assert_eq!(
        expected_command_codes.len(),
        tpml_cc.count as usize,
        "The number count field in TPML_CC did not contain the expected value"
    );

    expected_command_codes
        .iter()
        .zip(tpml_cc.commandCodes[0..tpml_cc.count as usize].iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                TPM2_CC::from(*expected),
                *actual,
                "Command code missmatch between command codes in CommandCodeList and converted CommandCodeList"
            )
        });

    let converted_command_code_list: CommandCodeList = tpml_cc
        .try_into()
        .expect("Failed to convert TPML_CC to CommandCodeList");

    assert_eq!(
        expected_command_codes.len(),
        converted_command_code_list.len(),
        "The command code list converted from TPML_CC did not contain the expected number of elements"
    );

    expected_command_codes
        .iter()
        .zip(converted_command_code_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual, "Command code in command code list converted from TPML_CC did not match the expected value"
            )
        });
}

#[test]
fn test_valid_conversion_vector() {
    let expected_command_codes = [
        CommandCode::ChangeEps,
        CommandCode::ChangePps,
        CommandCode::Clear,
    ];
    let mut command_code_list = CommandCodeList::new();
    for command_code in expected_command_codes.iter() {
        command_code_list
            .add(*command_code)
            .expect("Failed to add command code to command code list");
    }

    assert_eq!(
        expected_command_codes.len(),
        command_code_list.len(),
        "The created command code list did not contain the expected number of elements"
    );

    expected_command_codes
        .iter()
        .zip(command_code_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual,
                "The created command code list did not contain the expected value"
            )
        });

    let actual_command_codes: Vec<CommandCode> = command_code_list.into();

    assert_eq!(
        expected_command_codes.len(),
        actual_command_codes.len(),
        "The Vec<CommandCode> converted from CommandCodeList did not contain the expected number of elements"
    );

    expected_command_codes
        .iter()
        .zip(actual_command_codes.iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual, "Command code in command code list converted from TPML_CC did not match the expected value"
            )
        });
}

#[test]
fn test_invalid_conversions() {
    let mut command_code_list = CommandCodeList::new();
    for _ in 0..CommandCodeList::MAX_SIZE {
        command_code_list
            .add(CommandCode::ChangeEps)
            .expect("Failed to command code to list");
    }

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::WrongParamSize)),
        command_code_list.add(CommandCode::ChangeEps),
        "Adding more command codes to command code list then it supports did not produce the expected error"
    );
}

#[test]
fn test_invalid_conversion_from_tpml_cc() {
    let invalid_value = TPML_CC {
        count: CommandCodeList::MAX_SIZE as u32 + 1u32,
        commandCodes: [0; 256],
    };

    assert_eq!(
        Error::WrapperError(WrapperErrorKind::InvalidParam),
        CommandCodeList::try_from(invalid_value).expect_err(
            "Converting a TPML_CC with invalid values to CommandCodeList did not produce an error"
        ),
        "Converting invalid TPML_CC did not produce the expected error",
    );
}

#[test]
fn test_invalid_conversions_from_vector() {
    assert_eq!(
        Error::WrapperError(WrapperErrorKind::InvalidParam),
        CommandCodeList::try_from(vec![CommandCode::ChangeEps; CommandCodeList::MAX_SIZE + 1]).expect_err(
            "Converting Vec<CommandCode> of invalid length to CommandCodeList did not produce an error"
        ),
        "Converting invalid Vec<CommandCode> did not produce the expected error",
    );
}
