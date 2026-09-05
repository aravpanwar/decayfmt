// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    handles::KeyHandle,
    structures::{CreationData, CreationTicket, Digest, Private, Public},
};

#[allow(missing_debug_implementations)]
pub struct CreateKeyResult {
    pub out_private: Private,
    pub out_public: Public,
    pub creation_data: CreationData,
    pub creation_hash: Digest,
    pub creation_ticket: CreationTicket,
}

#[allow(missing_debug_implementations)]
pub struct CreatePrimaryKeyResult {
    pub key_handle: KeyHandle,
    pub out_public: Public,
    pub creation_data: CreationData,
    pub creation_hash: Digest,
    pub creation_ticket: CreationTicket,
}
