use tss_esapi::{
    abstraction::pcr::PcrData,
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest, DigestList, PcrSelectionListBuilder, PcrSlot},
    tss2_esys::TPML_DIGEST,
    Error, WrapperErrorKind,
};

use std::convert::TryFrom;

#[test]
fn test_valid_to_tpml_digest_conversion() {
    let pcr_selection_list_1 = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot0,
                PcrSlot::Slot1,
                PcrSlot::Slot2,
                PcrSlot::Slot3,
                PcrSlot::Slot4,
                PcrSlot::Slot5,
                PcrSlot::Slot6,
                PcrSlot::Slot7,
            ],
        )
        .build()
        .expect("Failed to create PcrSelectionList 1");

    let mut pcr_digest_list_1 = DigestList::new();
    for i in 0u8..8u8 {
        let value: [u8; 1] = [i];
        pcr_digest_list_1
            .add(Digest::try_from(&value[..]).expect("Failed to create digest value"))
            .expect("Failed to add value to digest");
    }

    let pcr_selection_list_2 = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot8,
                PcrSlot::Slot9,
                PcrSlot::Slot10,
                PcrSlot::Slot11,
                PcrSlot::Slot12,
                PcrSlot::Slot13,
                PcrSlot::Slot14,
                PcrSlot::Slot15,
            ],
        )
        .build()
        .expect("Failed to create PcrSelectionList 2");

    let mut pcr_digest_list_2 = DigestList::new();
    for i in 8u8..16u8 {
        let value: [u8; 1] = [i];
        pcr_digest_list_2
            .add(Digest::try_from(&value[..]).expect("Failed to create digest value"))
            .expect("Failed to add value to digest");
    }

    let mut pcr_data = PcrData::new();
    pcr_data
        .add(&pcr_selection_list_1, &pcr_digest_list_1)
        .expect("Failed to add selection and digests nr1");
    pcr_data
        .add(&pcr_selection_list_2, &pcr_digest_list_2)
        .expect("Failed to add selection and digests nr2");

    let tpml_digests: Vec<TPML_DIGEST> = pcr_data.into();
    assert_eq!(
        tpml_digests.len(),
        2,
        "PcrData did not convert into 2 TPML_DIGEST items as expected"
    );
    for (tpml_digest, count) in tpml_digests.iter().zip(0u8..2u8) {
        assert_eq!(
            tpml_digest.count as usize,
            DigestList::MAX_SIZE,
            "The converted digest list did not contain expected number of elements"
        );
        for (tpm2b_digest, value) in tpml_digest.digests.iter().zip(8 * count..8 * (count + 1)) {
            assert_eq!(
                tpm2b_digest.size, 1,
                "The converted digest did not contain expected number of bytes"
            );
            assert_eq!(
                tpm2b_digest.buffer[0], value,
                "The converted digest did not contain expected values"
            );
        }
    }
}

#[test]
fn test_invalid_to_tpml_digest_conversion() {
    let pcr_selection_list_1 = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot0,
                PcrSlot::Slot1,
                PcrSlot::Slot2,
                PcrSlot::Slot3,
                PcrSlot::Slot4,
                PcrSlot::Slot5,
                PcrSlot::Slot6,
                PcrSlot::Slot7,
            ],
        )
        .build()
        .expect("Failed to create PcrSelectionList 1");

    let mut pcr_digest_list_1 = DigestList::new();
    for i in 0u8..7u8 {
        let value: [u8; 1] = [i];
        pcr_digest_list_1
            .add(Digest::try_from(&value[..]).expect("Failed to create digest value"))
            .expect("Failed to add value to digest");
    }

    let mut pcr_data = PcrData::new();
    let pcr_data_add_result = pcr_data.add(&pcr_selection_list_1, &pcr_digest_list_1);

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InconsistentParams)),
        pcr_data_add_result,
        "Did not receive expected error"
    );
}
