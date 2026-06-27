//! decayfmt: a file format where decay is a first-class property.
//!
//! This crate currently exposes the foundation of the format: the typed error
//! model, the binary header, and the corruption algorithm. These are the parts
//! that must be correct before any encode, open, or CLI code is built on top of
//! them. The CLI binary and its encode and open flows are added in later milestones.

pub mod corrupt;
pub mod encode;
pub mod error;
pub mod format;
pub mod open;
