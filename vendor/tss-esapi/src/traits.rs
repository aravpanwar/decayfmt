// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::Result;

/// Trait for types that can be converted into
/// TPM marshalled data.
pub trait Marshall: Sized {
    const BUFFER_SIZE: usize;
    /// Returns the type in the form of marshalled data
    fn marshall(&self) -> Result<Vec<u8>>;
}

/// Trait for types that can be created from
/// TPM marshalled data.
pub trait UnMarshall: Sized {
    /// Creates the type from marshalled data.
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self>;
}
