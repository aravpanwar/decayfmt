// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! This module contains both the constants defined in the TSS specification (tss module)
//! but also the internal representation of the TSS constants.

/// Representation of the constants defined in the
/// Constants -> TPM_ALG_ID section of the specification
mod algorithm;
pub use algorithm::AlgorithmIdentifier;

/// The constants defined in the TSS specification.
#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    clippy::all
)]
/// Exposes the constants form the TSS header.
pub mod tss;

/// Representation of the constants defined in the
/// Constants -> TPM_ST section of the specification
pub mod structure_tags;

/// Representation of the constants defined in the
/// Constants -> TPM_PT section of the specification
pub mod property_tag;

/// Representation of the constants defined in the
/// Constants -> TPM_SU section of the specification
pub mod startup_type;

/// Representation of the constants defined in the
/// Constants -> TPM_SE section of the specification
pub mod session_type;

/// Representation of the constants defined in the
/// Constants -> TPM_CAP section of the specification
pub mod capabilities;

/// Representation of the return code TSS2_RC (TPM_RC)
pub mod response_code;

/// Representation of the constants defined in the
/// NV Storage -> TPM_NT section of the specification
pub mod nv_index_type;

/// Representation of the constants defined in
/// Constants -> TPM_ECC_CURVE section of the specification.
pub mod ecc;

/// Representation of the constants defined in
/// Constants -> TPM_CC section of the specification.
pub mod command_code;

/// Representation of the constants defined in
/// Constants -> TPM_PT_PCR section of the specification.
pub mod pcr_property_tag;

pub use capabilities::CapabilityType;
pub use command_code::CommandCode;
pub use ecc::EccCurveIdentifier;
pub use nv_index_type::NvIndexType;
pub use pcr_property_tag::PcrPropertyTag;
pub use property_tag::PropertyTag;
pub use response_code::{ResponseCode, Tss2ResponseCode, Tss2ResponseCodeKind};
pub use session_type::SessionType;
pub use startup_type::StartupType;
pub use structure_tags::StructureTag;
