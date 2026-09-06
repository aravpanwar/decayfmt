// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::{Digest, PcrSelectionList},
    tss2_esys::TPMS_QUOTE_INFO,
    Error, Result,
};
use std::convert::{TryFrom, TryInto};
/// Structure holding the attested data for TPM2_Quote()
///
/// # Details
/// This corresponds to the TPMS_QUOTE_INFO
#[derive(Debug, Clone)]
pub struct QuoteInfo {
    pcr_selection: PcrSelectionList,
    pcr_digest: Digest,
}

impl QuoteInfo {
    /// Returns the pcr selections list representing the selected PCRs.
    pub const fn pcr_selection(&self) -> &PcrSelectionList {
        &self.pcr_selection
    }

    /// Returns the digest selected PCRs hash of the signing key.
    pub const fn pcr_digest(&self) -> &Digest {
        &self.pcr_digest
    }
}

impl From<QuoteInfo> for TPMS_QUOTE_INFO {
    fn from(quote_info: QuoteInfo) -> Self {
        TPMS_QUOTE_INFO {
            pcrSelect: quote_info.pcr_selection.into(),
            pcrDigest: quote_info.pcr_digest.into(),
        }
    }
}

impl TryFrom<TPMS_QUOTE_INFO> for QuoteInfo {
    type Error = Error;

    fn try_from(tpms_quote_info: TPMS_QUOTE_INFO) -> Result<Self> {
        Ok(QuoteInfo {
            pcr_selection: tpms_quote_info.pcrSelect.try_into()?,
            pcr_digest: tpms_quote_info.pcrDigest.try_into()?,
        })
    }
}
