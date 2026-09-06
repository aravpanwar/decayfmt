// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::structures::Digest;
use crate::tss2_esys::TPML_DIGEST;
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::TryFrom;

#[derive(Debug, Clone, Default)]
pub struct DigestList {
    digests: Vec<Digest>,
}

impl DigestList {
    pub const MAX_SIZE: usize = 8;

    /// Creates a nnew empty DigestList
    pub const fn new() -> Self {
        DigestList {
            digests: Vec::new(),
        }
    }

    /// Returns the values in the digest list.
    pub fn value(&self) -> &[Digest] {
        &self.digests
    }

    /// Returns the number of digests in the digestlist
    pub fn len(&self) -> usize {
        self.digests.len()
    }

    /// Indicates if the digest list contains any digests.
    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// Adds a new digest to the digest list.
    pub fn add(&mut self, dig: Digest) -> Result<()> {
        if self.digests.len() >= DigestList::MAX_SIZE {
            error!("Exceeded maximum count(> {})", DigestList::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        self.digests.push(dig);
        Ok(())
    }
}

impl TryFrom<TPML_DIGEST> for DigestList {
    type Error = Error;
    fn try_from(tpml_digest: TPML_DIGEST) -> Result<Self> {
        let digests_count = tpml_digest.count as usize;

        if digests_count > DigestList::MAX_SIZE {
            error!("Invalid TPML_DIGEST count(> {})", DigestList::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        tpml_digest.digests[..digests_count]
            .iter()
            .map(|&tss_digest| Digest::try_from(tss_digest))
            .collect::<Result<Vec<Digest>>>()
            .map(|digests| DigestList { digests })
    }
}

impl TryFrom<DigestList> for TPML_DIGEST {
    type Error = Error;
    fn try_from(digest_list: DigestList) -> Result<Self> {
        if digest_list.digests.len() > DigestList::MAX_SIZE {
            error!("Invalid digest list size(> {})", DigestList::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }

        let mut tss_digest_list: TPML_DIGEST = Default::default();
        for digest in digest_list.digests {
            tss_digest_list.digests[tss_digest_list.count as usize] = digest.into();
            tss_digest_list.count += 1;
        }
        Ok(tss_digest_list)
    }
}
