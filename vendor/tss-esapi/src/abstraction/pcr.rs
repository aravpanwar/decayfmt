// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod bank;
mod data;

use crate::{structures::PcrSelectionList, Context, Result};

pub use bank::PcrBank;
pub use data::PcrData;

/// Function that reads all the PCRs in a selection list and returns
/// the result as PCR data.
///
/// # Example
///
/// ```rust
/// # use tss_esapi::{Context, TctiNameConf};
/// # // Create context
/// # let mut context =
/// #     Context::new(
/// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
/// #     ).expect("Failed to create Context");
/// #
/// use tss_esapi::{
///     interface_types::algorithm::HashingAlgorithm,
///     structures::{PcrSelectionListBuilder, PcrSlot},
/// };
/// // Create PCR selection list with slots in a bank
/// // that is going to be read.
/// let pcr_selection_list = PcrSelectionListBuilder::new()
///     .with_selection(HashingAlgorithm::Sha256,
///         &[
///             PcrSlot::Slot0,
///             PcrSlot::Slot1,
///             PcrSlot::Slot2,
///             PcrSlot::Slot3,
///             PcrSlot::Slot4,
///             PcrSlot::Slot5,
///             PcrSlot::Slot6,
///             PcrSlot::Slot7,
///             PcrSlot::Slot8,
///             PcrSlot::Slot9,
///             PcrSlot::Slot10,
///             PcrSlot::Slot11,
///             PcrSlot::Slot12,
///             PcrSlot::Slot13,
///             PcrSlot::Slot14,
///             PcrSlot::Slot15,
///             PcrSlot::Slot16,
///             PcrSlot::Slot17,
///             PcrSlot::Slot18,
///             PcrSlot::Slot19,
///             PcrSlot::Slot20,
///             PcrSlot::Slot21,
///     ])
///     .build()
///     .expect("Failed to build PcrSelectionList");
/// let _pcr_data = tss_esapi::abstraction::pcr::read_all(&mut context, pcr_selection_list)
///     .expect("pcr::read_all failed");
/// ```
pub fn read_all(
    context: &mut Context,
    mut pcr_selection_list: PcrSelectionList,
) -> Result<PcrData> {
    let mut pcr_data = PcrData::new();
    while !pcr_selection_list.is_empty() {
        let (_, pcrs_read, pcr_digests) = context.pcr_read(pcr_selection_list.clone())?;
        pcr_data.add(&pcrs_read, &pcr_digests)?;
        pcr_selection_list.subtract(&pcrs_read)?;
    }
    Ok(pcr_data)
}
