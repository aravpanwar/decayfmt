// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    attributes::CommandCodeAttributes, constants::CommandCode,
    structures::CommandCodeAttributesList, tss2_esys::TPML_CCA, Error, WrapperErrorKind,
};

#[test]
fn test_valid_conversions() {
    let expected_command_code_attributes = vec![
        CommandCodeAttributes::try_from(u32::from(CommandCode::NvUndefineSpaceSpecial)).expect(
            "Failed to create CommandCodeAttributes using CommandCode::NvUndefineSpaceSpecia",
        ),
        CommandCodeAttributes::try_from(u32::from(CommandCode::EvictControl))
            .expect("Failed to create CommandCodeAttributes using CommandCode::EvictControl"),
        CommandCodeAttributes::try_from(u32::from(CommandCode::PcrRead))
            .expect("Failed to create CommandCodeAttributes using CommandCode::PcrRead"),
    ];

    let expected_tpml_cca: TPML_CCA =
        expected_command_code_attributes
            .iter()
            .fold(Default::default(), |mut acc, &v| {
                acc.commandAttributes[acc.count as usize] = v.into();
                acc.count += 1;
                acc
            });

    let command_code_attributes_list_from_vec: CommandCodeAttributesList =
        expected_command_code_attributes
            .clone()
            .try_into()
            .expect("Failed to convert Vec<CommandCodeAttributes> to CommandCodeAttributesList");

    assert_eq!(
        expected_command_code_attributes.len(),
        command_code_attributes_list_from_vec.len(),
        "Mismatch in 'len()' between the Vec<CommandCodeAttributes> and the CommandCodeAttributesList(from vec)"
    );

    expected_command_code_attributes
        .iter()
        .zip(command_code_attributes_list_from_vec.as_ref())
        .for_each(|(expected, actual)| {
            assert_eq!(expected, actual, "Mismatch between an expected CommandCodeAttributes in the Vec<CommandCodeAttributes> the actual command code attributes in CommandCodeAttributesList(from vec)");
        });

    let command_code_attributes_list_from_tss: CommandCodeAttributesList = expected_tpml_cca
        .try_into()
        .expect("Failed to convert expected_tpml_cca into CommandCodeAttributesList");

    assert_eq!(
            expected_command_code_attributes.len(),
            command_code_attributes_list_from_tss.len(),
            "Mismatch in 'len()' between the Vec<CommandCodeAttributes> and the CommandCodeAttributesList(from tss)"
        );

    expected_command_code_attributes
        .iter()
        .zip(command_code_attributes_list_from_tss.as_ref())
        .for_each(|(expected, actual)| {
            assert_eq!(expected, actual, "Mismatch between an expected CommandCodeAttributes in the Vec<CommandCodeAttributes> the actual tagged property in CommandCodeAttributesList(from tss)");
        });

    let actual_tpml_cca: TPML_CCA = command_code_attributes_list_from_vec.into();

    crate::common::ensure_tpml_cca_equality(&expected_tpml_cca, &actual_tpml_cca);
}

#[test]
fn test_invalid_conversions() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        CommandCodeAttributesList::try_from(vec![CommandCodeAttributes::try_from(u32::from(CommandCode::NvUndefineSpaceSpecial)).expect(
            "Failed to create CommandCodeAttributes using CommandCode::NvUndefineSpaceSpecia",
        ); CommandCodeAttributesList::MAX_SIZE + 1]),
        "Converting a vector with to many elements into a CommandCodeAttributesList did not produce the expected error",
    );

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        CommandCodeAttributesList::try_from(TPML_CCA {
            count: CommandCodeAttributesList::MAX_SIZE as u32 + 1u32,
            commandAttributes: [Default::default(); 256],
        }),
        "Converting a TPML_CCA with an invalid 'count' value into a CommandCodeAttributesList did not produce the expected error",
    );
}

#[test]
fn test_find() {
    let command_code_attributes_list = CommandCodeAttributesList::try_from(vec![
        CommandCodeAttributes::try_from(u32::from(CommandCode::NvUndefineSpaceSpecial)).expect(
            "Failed to create CommandCodeAttributes using CommandCode::NvUndefineSpaceSpecial",
        ),
        CommandCodeAttributes::try_from(u32::from(CommandCode::EvictControl))
            .expect("Failed to create CommandCodeAttributes using CommandCode::EvictControl"),
        CommandCodeAttributes::try_from(u32::from(CommandCode::PcrRead))
            .expect("Failed to create CommandCodeAttributes using CommandCode::PcrRead"),
    ])
    .expect("Failed to convert Vec<CommandCodeAttributes> to CommandCodeAttributesList");

    assert_eq!(
        &CommandCodeAttributes::try_from(u32::from(CommandCode::NvUndefineSpaceSpecial)).expect(
            "Failed to create CommandCodeAttributes using CommandCode::NvUndefineSpaceSpecial",
        ),
        command_code_attributes_list
            .find(
                u16::try_from(u32::from(CommandCode::NvUndefineSpaceSpecial))
                .expect("Failed to convert CommandCode::NvUndefineSpaceSpecial into command code index")
            )
            .expect("Calling 'find' using CommandCode::NvUndefineSpaceSpecial as command code index returned an unexpected 'None'"),
        "Calling 'find' using CommandCode::NvUndefineSpaceSpecial as command code index did not return the expected CommandCodeAttributes value"
    );

    assert_eq!(
        &CommandCodeAttributes::try_from(u32::from(CommandCode::EvictControl)).expect(
            "Failed to create CommandCodeAttributes using CommandCode::EvictControl",
        ),
        command_code_attributes_list
            .find(
                u16::try_from(u32::from(CommandCode::EvictControl))
                .expect("Failed to convert CommandCode::EvictControl into command code index")
            )
            .expect("Calling 'find' using CommandCode::NvUndefineSpaceSpecial as command code index returned an unexpected 'None'"),
        "Calling 'find' using CommandCode::EvictControl as command code index did not return the expected CommandCodeAttributes value"
    );

    assert!(
        command_code_attributes_list
            .find(
                u16::try_from(u32::from(CommandCode::PcrAllocate))
                    .expect("Failed to convert CommandCode::PcrRead into command code index")
            )
            .is_none(),
        "A value that should not exist was found in the CommandCodeAttributesList"
    );
}
