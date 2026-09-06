// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    abstraction::pcr::PcrBank,
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest, DigestList, PcrSelectionList},
    tss2_esys::TPML_DIGEST,
    Error, Result, WrapperErrorKind,
};
use log::error;
/// Struct holding pcr banks and their associated
/// hashing algorithm
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrData {
    data: Vec<(HashingAlgorithm, PcrBank)>,
}

impl PcrData {
    /// Creates new empty PcrData
    pub const fn new() -> Self {
        PcrData { data: Vec::new() }
    }

    /// Function for creating PcrData from a pcr selection list and pcr digests list.
    pub fn create(
        pcr_selection_list: &PcrSelectionList,
        digest_list: &DigestList,
    ) -> Result<PcrData> {
        Ok(PcrData {
            data: Self::create_data(pcr_selection_list, digest_list.value().to_vec())?,
        })
    }

    /// Adds data to the PcrData
    pub fn add(
        &mut self,
        pcr_selection_list: &PcrSelectionList,
        digest_list: &DigestList,
    ) -> Result<()> {
        Self::create_data(pcr_selection_list, digest_list.value().to_vec())?
            .drain(..)
            .try_for_each(|(hashing_algorithm, pcr_bank)| {
                if let Some(existing_pcr_bank) = self.pcr_bank_mut(hashing_algorithm) {
                    existing_pcr_bank.try_extend(pcr_bank)?;
                } else {
                    self.data.push((hashing_algorithm, pcr_bank));
                }
                Ok(())
            })
    }

    /// Function for turning a pcr selection list and pcr digests values
    /// into the format in which data is stored in PcrData.
    fn create_data(
        pcr_selection_list: &PcrSelectionList,
        mut digests: Vec<Digest>,
    ) -> Result<Vec<(HashingAlgorithm, PcrBank)>> {
        pcr_selection_list
            .get_selections()
            .iter()
            .map(|pcr_selection| {
                let pcr_slots = pcr_selection.selected();
                if pcr_slots.len() > digests.len() {
                    error!("More pcr slots in selection then available digests");
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
                let digests_in_bank = digests.drain(..pcr_slots.len()).collect();
                Ok((
                    pcr_selection.hashing_algorithm(),
                    PcrBank::create(pcr_slots, digests_in_bank)?,
                ))
            })
            .collect()
    }

    /// Function for retrieving the first PCR values associated with hashing_algorithm.
    pub fn pcr_bank(&self, hashing_algorithm: HashingAlgorithm) -> Option<&PcrBank> {
        self.data
            .iter()
            .find(|(alg, _)| *alg == hashing_algorithm)
            .map(|(_, bank)| bank)
    }

    /// Function for retrieving the number of banks in the data.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if there are no banks in the data.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Private method for finding a PCR bank.
    fn pcr_bank_mut(&mut self, hashing_algorithm: HashingAlgorithm) -> Option<&mut PcrBank> {
        self.data
            .iter_mut()
            .find(|(alg, _)| *alg == hashing_algorithm)
            .map(|(_, bank)| bank)
    }
}

impl Default for PcrData {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for PcrData {
    type Item = (HashingAlgorithm, PcrBank);
    type IntoIter = ::std::vec::IntoIter<(HashingAlgorithm, PcrBank)>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl From<PcrData> for Vec<TPML_DIGEST> {
    fn from(pcr_data: PcrData) -> Self {
        pcr_data
            .data
            .iter()
            .flat_map(|(_, pcr_bank)| pcr_bank.into_iter())
            .map(|(_, digest)| digest)
            .collect::<Vec<&Digest>>()
            .chunks(DigestList::MAX_SIZE)
            .map(|digests| {
                let mut tpml_digest: TPML_DIGEST = Default::default();
                for (index, digest) in digests.iter().enumerate() {
                    tpml_digest.count += 1;
                    tpml_digest.digests[index].size = digest.len() as u16;
                    tpml_digest.digests[index].buffer[..digest.len()]
                        .copy_from_slice(digest.value());
                }
                tpml_digest
            })
            .collect()
    }
}
