// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::structures::{Digest, Name};

/// This structure contains the Name and hash of the
/// contents of the selected NV Index that is certified by
/// TPM2_NV_Certify()
///
/// # Details
/// This corresponds to  TPMS_NV_DIGEST_CERTIFY_INFO.
#[derive(Debug, Clone)]
pub struct NvDigestCertifyInfo {
    index_name: Name,
    nv_digest: Digest,
}

impl NvDigestCertifyInfo {
    /// Returns the index name
    pub const fn index_name(&self) -> &Name {
        &self.index_name
    }

    /// Returns the NV digest.
    pub const fn nv_digest(&self) -> &Digest {
        &self.nv_digest
    }
}
