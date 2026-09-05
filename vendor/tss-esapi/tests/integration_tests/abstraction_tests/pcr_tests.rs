// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::common::create_ctx_without_session;

use tss_esapi::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{PcrSelectionListBuilder, PcrSlot},
};

#[test]
fn test_pcr_read_all() {
    let mut context = create_ctx_without_session();

    let pcr_selection_list = PcrSelectionListBuilder::new()
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
                PcrSlot::Slot8,
                PcrSlot::Slot9,
                PcrSlot::Slot10,
                PcrSlot::Slot11,
                PcrSlot::Slot12,
                PcrSlot::Slot13,
                PcrSlot::Slot14,
                PcrSlot::Slot15,
                PcrSlot::Slot16,
                PcrSlot::Slot17,
                PcrSlot::Slot18,
                PcrSlot::Slot19,
                PcrSlot::Slot20,
                PcrSlot::Slot21,
                PcrSlot::Slot22,
                PcrSlot::Slot23,
            ],
        )
        .build()
        .expect("Failed to create PcrSelectionList for read_all call");

    let pcr_data = tss_esapi::abstraction::pcr::read_all(&mut context, pcr_selection_list)
        .expect("Call to pcr_read_all failed");

    assert_eq!(
        pcr_data
            .pcr_bank(HashingAlgorithm::Sha256)
            .expect("PcrData did not contain expected PcrBank")
            .len(),
        24,
        "PcrData did not contain expected amount of digests"
    );

    let (_count, _read_pcr_selection_1, read_pcrs_1) = context
        .pcr_read(
            PcrSelectionListBuilder::new()
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
                .expect("Failed to create PcrSekectinList for first pcr_read call"),
        )
        .expect("Call 1 to pcr_read failed");

    let (_count, _read_pcr_selection_2, read_pcrs_2) = context
        .pcr_read(
            PcrSelectionListBuilder::new()
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
                .expect("Failed to create PcrSekectinList for second pcr_read call"),
        )
        .expect("Call 2 to pcr_read failed");

    let (_count, _read_pcr_selection_3, read_pcrs_3) = context
        .pcr_read(
            PcrSelectionListBuilder::new()
                .with_selection(
                    HashingAlgorithm::Sha256,
                    &[
                        PcrSlot::Slot16,
                        PcrSlot::Slot17,
                        PcrSlot::Slot18,
                        PcrSlot::Slot19,
                        PcrSlot::Slot20,
                        PcrSlot::Slot21,
                        PcrSlot::Slot22,
                        PcrSlot::Slot23,
                    ],
                )
                .build()
                .expect("Failed to create PcrSekectinList for third pcr_read call"),
        )
        .expect("Call 3 to pcr_read failed");

    [read_pcrs_1, read_pcrs_2, read_pcrs_3]
        .iter()
        .enumerate()
        .for_each(|(idx, dl)| {
            assert_eq!(dl.len(), 8);
            let d = pcr_data
                .pcr_bank(HashingAlgorithm::Sha256)
                .expect("PcrData did not contain expected PcrBank")
                .into_iter()
                .skip(idx * 8)
                .take(8);
            assert_eq!(d.len(), 8);
            dl.value()
                .iter()
                .zip(d)
                .for_each(|(actual, (_, expected))| {
                    assert_eq!(actual, expected);
                })
        })
}
