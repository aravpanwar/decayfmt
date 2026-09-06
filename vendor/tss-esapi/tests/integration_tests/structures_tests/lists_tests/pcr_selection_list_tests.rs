// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{PcrSelectSize, PcrSelection, PcrSelectionList, PcrSlot},
    tss2_esys::{TPML_PCR_SELECTION, TPMS_PCR_SELECTION},
    Error, WrapperErrorKind,
};

#[test]
fn from_tpml_retains_order() {
    let selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot10],
    )
    .expect("Failed to create PcrSelection 1");
    let selection_1 = TPMS_PCR_SELECTION::from(selection_1);

    let selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot11],
    )
    .expect("Failed to create PcrSelection 2");
    let selection_2 = TPMS_PCR_SELECTION::from(selection_2);

    let selection_3 = PcrSelection::create(
        HashingAlgorithm::Sha1,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot16],
    )
    .expect("Failed to create PcrSelection 3");
    let selection_3 = TPMS_PCR_SELECTION::from(selection_3);

    let selection_4 = PcrSelection::create(
        HashingAlgorithm::Sha1,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot2],
    )
    .expect("Failed to create PcrSelection 4");
    let selection_4 = TPMS_PCR_SELECTION::from(selection_4);

    let tpml_selections = TPML_PCR_SELECTION {
        count: 4,
        pcrSelections: [
            selection_1,
            selection_2,
            selection_3,
            selection_4,
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
        ],
    };

    let selections = PcrSelectionList::try_from(tpml_selections).unwrap();
    let tpml_selections = TPML_PCR_SELECTION::from(selections);
    let selections = PcrSelectionList::try_from(tpml_selections).unwrap();

    assert_eq!(selections.len(), 4);

    let sel_1 = selections.get_selections()[0];
    let sel_2 = selections.get_selections()[1];
    let sel_3 = selections.get_selections()[2];
    let sel_4 = selections.get_selections()[3];

    assert_eq!(sel_1.hashing_algorithm(), HashingAlgorithm::Sha256);
    assert!(!sel_1.is_empty());
    assert!(sel_1.is_selected(PcrSlot::Slot10));
    assert!(!sel_1.is_selected(PcrSlot::Slot11));

    assert_eq!(sel_2.hashing_algorithm(), HashingAlgorithm::Sha256);
    assert!(!sel_2.is_empty());
    assert!(sel_2.is_selected(PcrSlot::Slot11));

    assert_eq!(sel_3.hashing_algorithm(), HashingAlgorithm::Sha1);
    assert!(!sel_3.is_empty());
    assert!(sel_3.is_selected(PcrSlot::Slot16));

    assert_eq!(sel_4.hashing_algorithm(), HashingAlgorithm::Sha1);
    assert!(!sel_4.is_empty());
    assert!(sel_4.is_selected(PcrSlot::Slot2));
}

#[test]
fn test_subtract() {
    let pcr_selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot10],
    )
    .expect("Failed to create PcrSelection 1");
    let tpms_pcr_selection_1 = TPMS_PCR_SELECTION::from(pcr_selection_1);

    let pcr_selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot11],
    )
    .expect("Failed to create PcrSelection 2");
    let tpms_pcr_selection_2 = TPMS_PCR_SELECTION::from(pcr_selection_2);

    let tpms_pcr_selection_3 = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha1,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot16],
        )
        .expect("Failed to create PcrSelection 3"),
    );

    let tpms_pcr_selection_4 = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha1,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot2],
        )
        .expect("Failed to create PcrSelection 4"),
    );

    let mut selection_list_1 = PcrSelectionList::try_from(TPML_PCR_SELECTION {
        count: 4,
        pcrSelections: [
            tpms_pcr_selection_1,
            tpms_pcr_selection_2,
            tpms_pcr_selection_3,
            tpms_pcr_selection_4,
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
        ],
    })
    .expect("Failed to convert selection list 1");

    let selection_list_2 = PcrSelectionList::try_from(TPML_PCR_SELECTION {
        count: 2,
        pcrSelections: [
            tpms_pcr_selection_3,
            tpms_pcr_selection_4,
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
        ],
    })
    .expect("Failed to convert selection list 2");

    selection_list_1
        .subtract(&selection_list_2)
        .expect("Failed to subtract selection_list_2 from selection_list_1");
    let selected_pcrs = selection_list_1.get_selections();
    assert_eq!(
        selected_pcrs.len(),
        2,
        "There are more pcr selections in the pcr selection list then expected"
    );
    assert_eq!(
        selected_pcrs[0], pcr_selection_1,
        "The first selection does not have expected values"
    );
    assert_eq!(
        selected_pcrs[1], pcr_selection_2,
        "The second selection does not have expected values"
    );
}

#[test]
fn test_subtract_overlapping_without_remaining() {
    let tpms_pcr_selection_1 = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha256,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot10],
        )
        .expect("Failed to create PcrSelection 1"),
    );
    let tpms_pcr_selection_2 = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha256,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot11],
        )
        .expect("Failed to create PcrSelection 2"),
    );

    let tpms_pcr_selection_3 = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha256,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot10, PcrSlot::Slot11],
        )
        .expect("Failed to create PcrSelection 3"),
    );

    let mut selection_list_1 = PcrSelectionList::try_from(TPML_PCR_SELECTION {
        count: 2,
        pcrSelections: [
            tpms_pcr_selection_1,
            tpms_pcr_selection_2,
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
        ],
    })
    .expect("Failed to convert selection list 1");

    let selection_list_2 = PcrSelectionList::try_from(TPML_PCR_SELECTION {
        count: 1,
        pcrSelections: [
            tpms_pcr_selection_3,
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
        ],
    })
    .expect("Failed to convert selection list 2");

    selection_list_1
        .subtract(&selection_list_2)
        .expect("Failed to subtract selection_list_2 from selection_list_1");
    let selected_pcrs = selection_list_1.get_selections();
    assert_eq!(
        selected_pcrs.len(),
        0,
        "There are more pcr selections in the pcr selection list then expected"
    );
}

#[test]
fn test_subtract_overlapping_with_remaining() {
    let tpms_pcr_selection_1 = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha256,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot10],
        )
        .expect("Failed to create PcrSelection 1"),
    );

    let tpms_pcr_selection_2 = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha256,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot11],
        )
        .expect("Failed to create PcrSelection 2"),
    );

    let expected = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot12],
    )
    .expect("Failed to create PcrSelection 'expected'");
    let tpms_pcr_selection_3 = TPMS_PCR_SELECTION::from(expected);

    let tpms_pcr_selection_4 = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha256,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot10, PcrSlot::Slot11],
        )
        .expect("Failed to create PcrSelection 4"),
    );

    let mut selection_list_1 = PcrSelectionList::try_from(TPML_PCR_SELECTION {
        count: 3,
        pcrSelections: [
            tpms_pcr_selection_1,
            tpms_pcr_selection_2,
            tpms_pcr_selection_3,
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
        ],
    })
    .expect("Failed to convert selection list 1");

    let selection_list_2 = PcrSelectionList::try_from(TPML_PCR_SELECTION {
        count: 1,
        pcrSelections: [
            tpms_pcr_selection_4,
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
        ],
    })
    .expect("Failed to convert selection list 2");

    selection_list_1
        .subtract(&selection_list_2)
        .expect("Failed to subtract selection_list_2 from selection_list_1");
    let selected_pcrs = selection_list_1.get_selections();
    assert_eq!(
        selected_pcrs.len(),
        1,
        "There are more pcr selections in the pcr selection list then expected"
    );
    assert_eq!(
        selected_pcrs[0], expected,
        "The first selection does not have expected values"
    );
}

#[test]
fn test_invalid_subtraction() {
    let pcr_selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot10],
    )
    .expect("Failed to create PcrSelection 1");
    let tpms_pcr_selection_1 = TPMS_PCR_SELECTION::from(pcr_selection_1);

    let pcr_selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot11],
    )
    .expect("Failed to create PcrSelection 2");
    let tpms_pcr_selection_2 = TPMS_PCR_SELECTION::from(pcr_selection_2);

    let tpms_pcr_selection_3 = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha1,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot16],
        )
        .expect("Failed to create PcrSelection 3"),
    );
    let tpms_pcr_selection_4 = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha1,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot2],
        )
        .expect("Failed to create PcrSelection 4"),
    );

    let mut selection_list_1 = PcrSelectionList::try_from(TPML_PCR_SELECTION {
        count: 2,
        pcrSelections: [
            tpms_pcr_selection_1,
            tpms_pcr_selection_2,
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
        ],
    })
    .expect("Failed to convert selection list 1");

    let selection_list_2 = PcrSelectionList::try_from(TPML_PCR_SELECTION {
        count: 4,
        pcrSelections: [
            tpms_pcr_selection_1,
            tpms_pcr_selection_2,
            tpms_pcr_selection_3,
            tpms_pcr_selection_4,
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
            TPMS_PCR_SELECTION::default(),
        ],
    })
    .expect("Failed to convert selection list 2");

    let subtract_result = selection_list_1.subtract(&selection_list_2);

    assert_eq!(
        subtract_result,
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "PcrSelectionList subtract method did not produce expected error for invalid parameters"
    );
}
