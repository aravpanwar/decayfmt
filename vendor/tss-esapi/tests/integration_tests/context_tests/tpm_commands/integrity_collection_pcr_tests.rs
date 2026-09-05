// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_pcr_extend_reset {
    use crate::common::create_ctx_with_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        abstraction::pcr::PcrData,
        handles::PcrHandle,
        interface_types::algorithm::HashingAlgorithm,
        structures::{Digest, DigestValues, PcrSelectionListBuilder, PcrSlot},
    };
    #[test]
    fn test_pcr_extend_reset_commands() {
        // In this test, we use PCR16. This was chosen because it's the only one that is
        // resettable and extendable from the locality in which we are running, and does not
        // get reset by any D-RTPM events.
        // PCR (TCG PC Client Platform TPM Profile (PTP) for TPM 2.0 Version 1.05 Rev 14)
        let mut context = create_ctx_with_session();
        let pcr_ses = context.sessions().0;

        // We start by resetting. We do not place any expectations on the prior contents
        context.execute_with_session(pcr_ses, |ctx| ctx.pcr_reset(PcrHandle::Pcr16).unwrap());

        // Read PCR contents
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot16])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot16])
            .build()
            .expect("Failed to create first PcrSelectionList for pcr_read call");
        // pcr_read is NO_SESSIONS
        let (_, read_pcr_selections, read_pcr_digests) = context.execute_without_session(|ctx| {
            ctx.pcr_read(pcr_selection_list.clone())
                .expect("Failed to call pcr_read")
        });

        // Needs to have the length of associated with the hashing algorithm
        read_pcr_selections
            .get_selections()
            .iter()
            .zip(read_pcr_digests.value().iter())
            .for_each(|(pcr_selection, digest)| {
                if pcr_selection.hashing_algorithm() == HashingAlgorithm::Sha1 {
                    assert_eq!(digest.len(), 20);
                    assert_eq!(digest.value(), [0; 20]);
                } else if pcr_selection.hashing_algorithm() == HashingAlgorithm::Sha256 {
                    assert_eq!(digest.len(), 32);
                    assert_eq!(digest.value(), [0; 32]);
                } else {
                    panic!("Read pcr selections contained unexpected HashingAlgorithm");
                }
            });

        // Extend both sha256 and sha1
        let mut vals = DigestValues::new();
        vals.set(
            HashingAlgorithm::Sha1,
            Digest::try_from(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            ])
            .unwrap(),
        );
        vals.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ])
            .unwrap(),
        );
        // The extend and reset functions are all SESSIONS
        context.execute_with_session(pcr_ses, |ctx| {
            ctx.pcr_extend(PcrHandle::Pcr16, vals).unwrap()
        });

        // Read PCR contents
        let (_, read_pcr_selections_2, read_pcr_digests_2) =
            context.execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list).unwrap());
        // Needs to have the length of associated with the hashing algorithm
        /*
          Right Hand Side determined by:
          python3
          >>> from hashlib import sha1
          >>> m = sha1()
          >>> m.update(b"\0" * 20)
          >>> m.update(bytes(range(1,21)))
          >>> it = iter(m.hexdigest())
          >>> res = ["0x"+a+b for a,b in zip(it, it)]
          >>> ", ".join(res)
        */

        read_pcr_selections_2
            .get_selections()
            .iter()
            .zip(read_pcr_digests_2.value().iter())
            .for_each(|(pcr_selection, digest)| {
                if pcr_selection.hashing_algorithm() == HashingAlgorithm::Sha1 {
                    assert_eq!(digest.len(), 20);
                    assert_eq!(
                        digest.value(),
                        [
                            0x5f, 0x42, 0x0e, 0x04, 0x95, 0x8b, 0x2e, 0x3f, 0x18, 0x07, 0x39, 0x1e,
                            0x99, 0xd9, 0x49, 0x2c, 0x67, 0xaa, 0xef, 0xfd
                        ]
                    );
                } else if pcr_selection.hashing_algorithm() == HashingAlgorithm::Sha256 {
                    assert_eq!(digest.len(), 32);
                    assert_eq!(
                        digest.value(),
                        [
                            0x0b, 0x8f, 0x4c, 0x5b, 0x6a, 0xdc, 0x4c, 0x08, 0x7a, 0xb9, 0xf4, 0x3a,
                            0xae, 0xb6, 0x00, 0x70, 0x84, 0xc2, 0x64, 0xad, 0xca, 0xa3, 0xcb, 0x07,
                            0x17, 0x6b, 0x79, 0x23, 0x42, 0x85, 0x04, 0x12
                        ]
                    );
                } else {
                    panic!("Read pcr selections contained unexpected HashingAlgorithm");
                }
            });

        // Now reset it again to test it's again zeroes
        context.execute_with_session(pcr_ses, |ctx| ctx.pcr_reset(PcrHandle::Pcr16).unwrap());

        // Read PCR contents
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot16])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot16])
            .build()
            .expect("Failed to create PcrSelectionList for pcr_read call after pcr_reset");
        let pcr_data = context
            .execute_without_session(|ctx| {
                ctx.pcr_read(pcr_selection_list).map(
                    |(_, read_pcr_selections, read_pcr_digests)| {
                        PcrData::create(&read_pcr_selections, &read_pcr_digests)
                            .expect("Failed to create PcrData")
                    },
                )
            })
            .expect("Failed to call pcr_read");
        let pcr_sha1_bank = pcr_data.pcr_bank(HashingAlgorithm::Sha1).unwrap();
        let pcr_sha256_bank = pcr_data.pcr_bank(HashingAlgorithm::Sha256).unwrap();
        let pcr_sha1_value = pcr_sha1_bank.get_digest(PcrSlot::Slot16).unwrap();
        let pcr_sha256_value = pcr_sha256_bank.get_digest(PcrSlot::Slot16).unwrap();
        // Needs to have the length of associated with the hashing algorithm
        assert_eq!(pcr_sha1_value.value(), [0; 20]);
        assert_eq!(pcr_sha256_value.value(), [0; 32]);
    }
}

mod test_pcr_read {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        interface_types::algorithm::HashingAlgorithm,
        structures::{PcrSelectionListBuilder, PcrSlot},
        tss2_esys::{TPM2_SHA256_DIGEST_SIZE, TPML_PCR_SELECTION},
    };

    #[test]
    fn test_pcr_read_command() {
        let mut context = create_ctx_without_session();
        // Read PCR 0
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
            .build()
            .expect("Failed to create PcrSelectionList");
        let input: TPML_PCR_SELECTION = pcr_selection_list.clone().into();
        // Verify input
        assert_eq!(pcr_selection_list.len(), 1);
        assert_eq!(input.count as usize, pcr_selection_list.len());
        assert_eq!(input.pcrSelections[0].sizeofSelect, 3);
        assert_eq!(input.pcrSelections[0].hash, HashingAlgorithm::Sha256.into());
        assert_eq!(input.pcrSelections[0].pcrSelect[0], 0b0000_0001);
        assert_eq!(input.pcrSelections[0].pcrSelect[1], 0b0000_0000);
        assert_eq!(input.pcrSelections[0].pcrSelect[2], 0b0000_0000);
        // Read the pcr slots.
        let (update_counter, read_pcr_selections, read_pcr_digests) = context
            .pcr_read(pcr_selection_list)
            .expect("Failed to call pcr_read");

        // Verify that the selected slots have been read.
        assert_ne!(update_counter, 0);
        let output: TPML_PCR_SELECTION = read_pcr_selections.into();
        assert_eq!(output.count, input.count);
        assert_eq!(
            output.pcrSelections[0].sizeofSelect,
            input.pcrSelections[0].sizeofSelect
        );
        assert_eq!(input.pcrSelections[0].hash, output.pcrSelections[0].hash);
        assert_eq!(
            input.pcrSelections[0].pcrSelect[0],
            output.pcrSelections[0].pcrSelect[0]
        );
        assert_eq!(
            input.pcrSelections[0].pcrSelect[1],
            output.pcrSelections[0].pcrSelect[1]
        );
        assert_eq!(
            input.pcrSelections[0].pcrSelect[2],
            output.pcrSelections[0].pcrSelect[2]
        );

        // Only the specified in the selection should be present.
        assert_eq!(read_pcr_digests.len(), 1);
        assert_eq!(read_pcr_digests.len(), output.count as usize);
        // Needs to have the length of associated with the hashing algorithm
        assert_eq!(
            read_pcr_digests.value()[0].len(),
            TPM2_SHA256_DIGEST_SIZE as usize
        );
    }

    #[test]
    fn test_pcr_read_large_pcr_selections() {
        // If the pcr Selection contains more then 16 values
        // then not all can be read at once and the returned
        // pcr selections will differ from the original.
        let mut context = create_ctx_without_session();
        let pcr_selection_list_in = PcrSelectionListBuilder::new()
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
                ],
            )
            .build()
            .expect("Failed to create PcrSelectionList");
        let (_update_counter, pcr_selection_list_out, _pcr_data) = context
            .pcr_read(pcr_selection_list_in.clone())
            .expect("pcr_read call failed");
        assert_ne!(pcr_selection_list_in, pcr_selection_list_out);
    }
}
