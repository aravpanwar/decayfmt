// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! This module contains the different interface types defined in
//! the TPM 2.0 specification.
mod yes_no;

pub mod algorithm;
pub mod dynamic_handles;
pub mod ecc;
pub mod key_bits;
pub mod resource_handles;
pub mod session_handles;
pub mod structure_tags;

pub use yes_no::YesNo;
