// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::tss::{TPM2_ALG_SHA256, TPM2_ALG_SHA512},
    interface_types::algorithm::HashingAlgorithm,
    structures::{PcrSelectSize, PcrSelection, PcrSlot},
    tss2_esys::TPMS_PCR_SELECTION,
    Error, WrapperErrorKind,
};

#[test]
fn test_conversion_to_tss_pcr_selection() {
    let actual = TPMS_PCR_SELECTION::from(
        PcrSelection::create(
            HashingAlgorithm::Sha512,
            PcrSelectSize::ThreeOctets,
            &[PcrSlot::Slot3, PcrSlot::Slot9, PcrSlot::Slot23],
        )
        .expect("Failed to create pcr selection"),
    );
    let expected = TPMS_PCR_SELECTION {
        hash: TPM2_ALG_SHA512,
        sizeofSelect: 3,
        pcrSelect: [8, 2, 128, 0],
    };
    assert_eq!(expected.hash, actual.hash);
    assert_eq!(expected.sizeofSelect, actual.sizeofSelect);
    assert_eq!(expected.pcrSelect, actual.pcrSelect);
}

#[test]
fn test_conversion_from_tss_pcr_selection() {
    let actual = PcrSelection::try_from(TPMS_PCR_SELECTION {
        hash: TPM2_ALG_SHA256,
        sizeofSelect: 2,
        pcrSelect: [16, 128, 0, 0],
    })
    .unwrap();
    let expected = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot4, PcrSlot::Slot15],
    )
    .expect("Failed to create pcr selection");
    assert_eq!(expected, actual);
}

#[test]
fn test_size_of_select_handling() {
    let actual = PcrSelection::try_from(TPMS_PCR_SELECTION {
        hash: TPM2_ALG_SHA256,
        sizeofSelect: 2,
        pcrSelect: [16, 128, 5, 1],
    })
    .expect("Failed to convert TPMS_PCR_SELECTION into a PcrSelection");

    // Size of select is 2 so the values in octet 3 and 4
    // should not appear in the converted pcr selection.

    let expected = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot4, PcrSlot::Slot15],
    )
    .expect("Failed to create PcrSelection");
    assert_eq!(expected, actual);
}

#[test]
fn test_subtract() {
    let mut pcr_selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot4, PcrSlot::Slot15],
    )
    .expect("Failed to create PcrSelection pcr_selection_1");

    let pcr_selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot4],
    )
    .expect("Failed to create PcrSelection pcr_selection_2");

    pcr_selection_1
        .subtract_exact(&pcr_selection_2)
        .expect("Failed to subtract pcr_selection_2 from pcr_selection_1");

    assert_eq!(
        pcr_selection_1.hashing_algorithm(),
        HashingAlgorithm::Sha256,
        "The pcr_selection_1 did not contain expected HashingAlgorithm after subtract"
    );

    assert_eq!(
        pcr_selection_1.size_of_select(),
        PcrSelectSize::TwoOctets,
        "The pcr_selection_1 did not have the expected size of select after subtract"
    );

    assert_eq!(
        pcr_selection_1.selected(),
        vec![PcrSlot::Slot15],
        "The pcr_selection_1 did not contain expected PcrSlots after subtract"
    );
}

#[test]
fn test_deselect() {
    let mut pcr_selection = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[
            PcrSlot::Slot4,
            PcrSlot::Slot5,
            PcrSlot::Slot6,
            PcrSlot::Slot7,
            PcrSlot::Slot15,
        ],
    )
    .expect("Failed to create PcrSelection pcr_selection");

    pcr_selection.deselect(PcrSlot::Slot7);

    assert_eq!(
        PcrSelection::create(
            HashingAlgorithm::Sha256,
            PcrSelectSize::TwoOctets,
            &[
                PcrSlot::Slot4,
                PcrSlot::Slot5,
                PcrSlot::Slot6,
                PcrSlot::Slot15,
            ],
        )
        .expect("Failed to create PcrSelection"),
        pcr_selection,
        "PcrSelection did not match expected value after calling deselect."
    )
}

#[test]
fn test_merge_exact() {
    let mut pcr_selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot4, PcrSlot::Slot15],
    )
    .expect("Failed to create PcrSelection pcr_selection_1");

    let pcr_selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot5],
    )
    .expect("Failed to create PcrSelection pcr_selection_2");

    pcr_selection_1
        .merge_exact(&pcr_selection_2)
        .expect("Failed to exactly merge pcr_selection_2 into pcr_selection_1");

    assert_eq!(
        PcrSelection::create(
            HashingAlgorithm::Sha256,
            PcrSelectSize::TwoOctets,
            &[PcrSlot::Slot4, PcrSlot::Slot5, PcrSlot::Slot15],
        )
        .expect("Failed to create PcrSelection"),
        pcr_selection_1,
        "PcrSelection did not contain expected value calling merge_exact",
    );
}

#[test]
fn test_merge_exact_hashing_algorithm_mismatch_errors() {
    let mut pcr_selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot5],
    )
    .expect("Failed to create PcrSelection pcr_selection_1");

    let pcr_selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha384,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot6],
    )
    .expect("Failed to create PcrSelection pcr_selection_2");

    assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
            pcr_selection_1.merge_exact(&pcr_selection_2),
            "Merge exact PcrSelections with different hashing algorithm did not produce the expected error",
        );
}

#[test]
fn test_merge_exact_size_of_select_mismatch_errors() {
    let mut pcr_selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot5],
    )
    .expect("Failed to create PcrSelection pcr_selection_1");

    let pcr_selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot6],
    )
    .expect("Failed to create PcrSelection pcr_selection_2");

    assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
            pcr_selection_1.merge_exact(&pcr_selection_2),
            "Merge exact PcrSelections with different size of select did not produce the expected error",
        );
}

#[test]
fn test_merge_exact_non_unique_pcr_slot_errors() {
    let mut pcr_selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot5],
    )
    .expect("Failed to create PcrSelection pcr_selection_1");

    let pcr_selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot5],
    )
    .expect("Failed to create PcrSelection pcr_selection_2");

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        pcr_selection_1.merge_exact(&pcr_selection_2),
        "Merge exact PcrSelections with non unique PcrSlot did not produce the expected error",
    );
}

#[test]
fn test_subtract_exact_hashing_algorithm_mismatch_errors() {
    let mut pcr_selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot5],
    )
    .expect("Failed to create PcrSelection pcr_selection_1");

    let pcr_selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha384,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot5],
    )
    .expect("Failed to create PcrSelection pcr_selection_2");

    assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InconsistentParams)),
            pcr_selection_1.subtract_exact(&pcr_selection_2),
            "Subtract exact PcrSelections with different hashing algorithm did not produce the expected error",
        );
}

#[test]
fn test_subtract_exact_size_of_select_mismatch_errors() {
    let mut pcr_selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot5],
    )
    .expect("Failed to create PcrSelection pcr_selection_1");

    let pcr_selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoOctets,
        &[PcrSlot::Slot5],
    )
    .expect("Failed to create PcrSelection pcr_selection_2");

    assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
            pcr_selection_1.subtract_exact(&pcr_selection_2),
            "Subtract exact PcrSelections with different size of select did not produce the expected error",
        );
}

#[test]
fn test_subtract_exact_unique_pcr_slot_errors() {
    let mut pcr_selection_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot5],
    )
    .expect("Failed to create PcrSelection pcr_selection_1");

    let pcr_selection_2 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::ThreeOctets,
        &[PcrSlot::Slot6],
    )
    .expect("Failed to create PcrSelection pcr_selection_2");

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        pcr_selection_1.subtract_exact(&pcr_selection_2),
        "Subtract exact PcrSelections with unique PcrSlot did not produce the expected error",
    );
}
