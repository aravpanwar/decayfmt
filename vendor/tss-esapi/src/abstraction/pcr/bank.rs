// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::{Digest, PcrSlot},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::collections::BTreeMap;

/// Struct for holding PcrSlots and their
/// corresponding values.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PcrBank {
    bank: BTreeMap<PcrSlot, Digest>,
}

impl PcrBank {
    /// Function that creates PcrBank from a vector of pcr slots and
    /// a vector of pcr digests.
    ///
    /// # Details
    /// The order of pcr slots are assumed to match the order of the Digests.
    ///
    /// # Errors
    /// - If number of pcr slots does not match the number of pcr digests
    ///   InconsistentParams error is returned.
    ///
    /// - If the vector of pcr slots contains duplicates then
    ///   InconsistentParams error is returned.
    pub fn create(mut pcr_slots: Vec<PcrSlot>, mut digests: Vec<Digest>) -> Result<PcrBank> {
        if pcr_slots.len() != digests.len() {
            error!(
                "Number of PcrSlots does not match the number of PCR digests. ({} != {})",
                pcr_slots.len(),
                digests.len()
            );
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }
        pcr_slots
            .drain(..)
            .zip(digests.drain(..))
            .try_fold(BTreeMap::<PcrSlot, Digest>::new(), |mut data, (pcr_slot, digest)| {
                if data.insert(pcr_slot, digest).is_none() {
                    Ok(data)
                } else {
                    error!("Error trying to insert data into PcrSlot {:?} where data have already been inserted", pcr_slot);
                    Err(Error::local_error(WrapperErrorKind::InconsistentParams))
                }
            })
            .map(|bank|  PcrBank { bank })
    }

    /// Retrieves reference to a [Digest] associated with the provided [PcrSlot].
    ///
    /// # Details
    /// Returns a reference to a [Digest] associated with the provided [PcrSlot]
    /// if one exists else returns None.
    pub fn get_digest(&self, pcr_slot: PcrSlot) -> Option<&Digest> {
        self.bank.get(&pcr_slot)
    }

    /// Returns true if the [PcrBank] contains a digest
    /// for the provided [PcrSlot].
    pub fn has_digest(&self, pcr_slot: PcrSlot) -> bool {
        self.bank.contains_key(&pcr_slot)
    }

    /// Number of digests in the [PcrBank]
    pub fn len(&self) -> usize {
        self.bank.len()
    }

    /// Returns true if the [PcrBank] is empty
    pub fn is_empty(&self) -> bool {
        self.bank.is_empty()
    }

    /// Removees the [Digest] associated with the [PcrSlot] and
    /// returns it.
    ///
    /// # Details
    /// Removes the [Digest] associated with the provided [PcrSlot]
    /// out of the bank and returns it if it exists else returns None.
    pub fn remove_digest(&mut self, pcr_slot: PcrSlot) -> Option<Digest> {
        self.bank.remove(&pcr_slot)
    }

    /// Inserts [Digest] value associated with a [PcrSlot] into the bank.
    ///
    /// # Errors
    /// Returns an error if a [Digest] is already associated with the
    /// provided [PcrSlot].
    pub fn insert_digest(&mut self, pcr_slot: PcrSlot, digest: Digest) -> Result<()> {
        self.ensure_non_existing(pcr_slot, "Failed to insert")?;
        let _ = self.bank.insert(pcr_slot, digest);
        Ok(())
    }

    /// Attempts to extend the [PcrBank] with `other`.
    ///
    /// # Errors
    /// Returns an error if the a value in `other` already
    /// exists.
    pub fn try_extend(&mut self, other: PcrBank) -> Result<()> {
        other
            .bank
            .keys()
            .try_for_each(|&pcr_slot| self.ensure_non_existing(pcr_slot, "Failed to extend"))?;
        self.bank.extend(other.bank);
        Ok(())
    }

    /// Returns an error if a [Digest] for [PcrSlot] already exists in the bank
    fn ensure_non_existing(&self, pcr_slot: PcrSlot, error_msg: &str) -> Result<()> {
        if self.has_digest(pcr_slot) {
            error!(
                "{}, a digest already for PcrSlot {:?} exists in the bank",
                error_msg, pcr_slot
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(())
    }
}

impl<'a> IntoIterator for &'a PcrBank {
    type Item = (&'a PcrSlot, &'a Digest);
    type IntoIter = ::std::collections::btree_map::Iter<'a, PcrSlot, Digest>;

    fn into_iter(self) -> Self::IntoIter {
        self.bank.iter()
    }
}
