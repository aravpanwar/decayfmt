//! Module for representation of attributes

/// Representation of the attributes defined in the
/// Attribute structures -> TPMA_OBJECT section of
/// the specification
pub mod object;

/// Representation of the attributes defined in the
/// Attribute structures -> TPMA_OBJECT section of
/// the specification.
pub mod session;

/// Representation of the attributes defined in the
/// NV Storage -> TPMA_NV section of
/// the specification.
pub mod nv_index;

pub mod locality;

pub mod algorithm;

pub mod command_code;

pub use algorithm::AlgorithmAttributes;
pub use command_code::CommandCodeAttributes;
pub use locality::{LocalityAttributes, LocalityAttributesBuilder};
pub use nv_index::{NvIndexAttributes, NvIndexAttributesBuilder};
pub use object::{ObjectAttributes, ObjectAttributesBuilder};
pub use session::{SessionAttributes, SessionAttributesBuilder, SessionAttributesMask};
