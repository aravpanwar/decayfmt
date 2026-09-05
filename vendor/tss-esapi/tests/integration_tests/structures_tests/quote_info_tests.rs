// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest, PcrSelectionListBuilder, PcrSlot, QuoteInfo},
    tss2_esys::TPMS_QUOTE_INFO,
};

#[test]
fn test_conversion() {
    let expected_pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot1,
                PcrSlot::Slot2,
                PcrSlot::Slot3,
                PcrSlot::Slot4,
            ],
        )
        .build()
        .expect("Failed to pcr selection list");
    let expected_pcr_digest = Digest::try_from(vec![0xffu8; 32]).expect("Failed to create digest");
    let expected_tpms_quote_info = TPMS_QUOTE_INFO {
        pcrSelect: expected_pcr_selection.clone().into(),
        pcrDigest: expected_pcr_digest.clone().into(),
    };
    let quote_info = QuoteInfo::try_from(expected_tpms_quote_info)
        .expect("Failed to create QuoteInfo from TPMS_QUOTE_INFO");

    assert_eq!(
        &expected_pcr_selection,
        quote_info.pcr_selection(),
        "The QuoteInfo converted from TPMS_QUOTE_INFO did not contain the expected PCR selection"
    );
    assert_eq!(
        &expected_pcr_digest,
        quote_info.pcr_digest(),
        "The QuoteInfo converted from TPMS_QUOTE_INFO did not contain the expected PCR digest"
    );

    let actual_tpms_quote_info: TPMS_QUOTE_INFO = quote_info.into();

    crate::common::ensure_tpms_quote_info_equality(
        &expected_tpms_quote_info,
        &actual_tpms_quote_info,
    );
}
