// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use num_traits::ToPrimitive;
use std::convert::TryFrom;
use tss_esapi::{
    constants::tss::TPM2_ALG_LAST,
    interface_types::algorithm::HashingAlgorithm,
    structures::{PcrSelectSize, PcrSelectionList, PcrSelectionListBuilder, PcrSlot},
    tss2_esys::{TPM2_ALG_ID, TPML_PCR_SELECTION},
};

#[test]
fn test_one_selection() {
    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
        )
        .build()
        .expect("Failed to createm PcrSelectionList");

    let pcr_selection_list_size = pcr_selection_list.len();
    let actual: TPML_PCR_SELECTION = pcr_selection_list.into();
    assert_eq!(actual.count as usize, pcr_selection_list_size);
    // No size has been chosen so the default will be set.
    assert_eq!(
        actual.pcrSelections[0].sizeofSelect,
        PcrSelectSize::default().to_u8().unwrap()
    );
    assert_eq!(
        actual.pcrSelections[0].hash,
        Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sha256)
    );
    assert_eq!(actual.pcrSelections[0].pcrSelect[0], 0b0000_0001);
    assert_eq!(actual.pcrSelections[0].pcrSelect[1], 0b0000_0001);
    assert_eq!(actual.pcrSelections[0].pcrSelect[2], 0b0000_0001);
}

#[test]
fn test_multiple_selection() {
    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
        )
        .with_selection(
            HashingAlgorithm::Sha1,
            &[
                PcrSlot::Slot1,
                PcrSlot::Slot8,
                PcrSlot::Slot10,
                PcrSlot::Slot20,
                PcrSlot::Slot23,
            ],
        )
        .build()
        .expect("Failed to createm PcrSelectionList");

    let pcr_selection_list_size = pcr_selection_list.len();
    let actual: TPML_PCR_SELECTION = pcr_selection_list.into();
    assert_eq!(actual.count as usize, pcr_selection_list_size);
    for pcr_selection in actual.pcrSelections[..actual.count as usize].iter() {
        assert_eq!(
            pcr_selection.sizeofSelect,
            PcrSelectSize::default().to_u8().unwrap()
        );
        // The order is not specified.
        match HashingAlgorithm::try_from(pcr_selection.hash).unwrap() {
            HashingAlgorithm::Sha256 => {
                assert_eq!(pcr_selection.pcrSelect[0], 0b0000_0001);
                assert_eq!(pcr_selection.pcrSelect[1], 0b0000_0001);
                assert_eq!(pcr_selection.pcrSelect[2], 0b0000_0001);
            }
            HashingAlgorithm::Sha1 => {
                assert_eq!(pcr_selection.pcrSelect[0], 0b0000_0010);
                assert_eq!(pcr_selection.pcrSelect[1], 0b0000_0101);
                assert_eq!(pcr_selection.pcrSelect[2], 0b1001_0000);
            }
            _ => panic!("Encountered incorrect Hashing Algorithm"),
        }
    }
}

#[test]
fn test_multiple_conversions() {
    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_size_of_select(Default::default())
        .with_selection(
            HashingAlgorithm::Sha256,
            &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
        )
        .build()
        .expect("Failed to create PcrSelectionList");
    let pcr_selection_list_size = pcr_selection_list.len();
    let converted: TPML_PCR_SELECTION = pcr_selection_list.into();
    assert_eq!(converted.count as usize, pcr_selection_list_size);

    let from_converted = PcrSelectionList::try_from(converted).unwrap();
    let re_converted: TPML_PCR_SELECTION = from_converted.into();

    assert_eq!(converted.count, re_converted.count);
    assert_eq!(
        converted.pcrSelections[0].sizeofSelect,
        re_converted.pcrSelections[0].sizeofSelect
    );
    assert_eq!(
        converted.pcrSelections[0].hash,
        re_converted.pcrSelections[0].hash
    );
    assert_eq!(
        converted.pcrSelections[0].pcrSelect[0],
        re_converted.pcrSelections[0].pcrSelect[0]
    );
    assert_eq!(
        converted.pcrSelections[0].pcrSelect[1],
        re_converted.pcrSelections[0].pcrSelect[1]
    );
    assert_eq!(
        converted.pcrSelections[0].pcrSelect[2],
        re_converted.pcrSelections[0].pcrSelect[2]
    );
}

#[test]
fn test_conversion_of_data_with_invalid_pcr_select_bit_flags() {
    let expected_hash_algorithm = HashingAlgorithm::Sha256;
    let expected_pcr_slots = [PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16];
    let mut tpml_pcr_selection: TPML_PCR_SELECTION = PcrSelectionListBuilder::new()
        .with_selection(expected_hash_algorithm, &expected_pcr_slots)
        .build()
        .expect("Failed to create PcrSelectionList")
        .into();

    // Size of select is 3 indicating that only 3 first octets
    // should be parsed. Setting a value in the fourth
    // octet should not in any way affect the result.
    tpml_pcr_selection.pcrSelections[0].pcrSelect[3] = 1;

    let pcr_selection_list = PcrSelectionList::try_from(tpml_pcr_selection)
        .expect("Failed to parse TPML_PCR_SELECTION as PcrSelectionList");

    assert_eq!(
        pcr_selection_list.len(),
        1,
        "The converted pcr selection list contained more items then expected"
    );

    assert_eq!(
        pcr_selection_list.get_selections()[0].size_of_select(),
        PcrSelectSize::ThreeOctets,
        "PcrSelection in index 0, in the converted pcr selection list, contained an unexpected 'size of select' value",
    );

    assert_eq!(
        &pcr_selection_list.get_selections()[0].selected(),
        &expected_pcr_slots,
        "PcrSelection in index 0, in the converted pcr selection list, contained one or more unexpected PcrSlot values",
    );
}

#[test]
fn test_conversion_of_data_with_invalid_size_of_select() {
    let mut tpml_pcr_selection: TPML_PCR_SELECTION = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
        )
        .build()
        .expect("Failed to create PcrSelectionList")
        .into();

    // 1,2,3,4 are theonly valid values for sizeofSelect.
    tpml_pcr_selection.pcrSelections[0].sizeofSelect = 20;

    // The try_from should then fail.
    PcrSelectionList::try_from(tpml_pcr_selection).unwrap_err();
}

#[test]
fn test_conversion_of_data_with_invalid_hash_alg_id() {
    let mut tpml_pcr_selection: TPML_PCR_SELECTION = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
        )
        .build()
        .expect("Failed to create PcrSelectionList")
        .into();

    // Si
    tpml_pcr_selection.pcrSelections[0].hash = TPM2_ALG_LAST + 1;

    // The try_from should then fail.
    PcrSelectionList::try_from(tpml_pcr_selection).unwrap_err();
}
