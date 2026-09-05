// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![deny(
    nonstandard_style,
    dead_code,
    improper_ctypes,
    non_shorthand_field_patterns,
    no_mangle_generic_items,
    overflowing_literals,
    path_statements,
    patterns_in_fns_without_body,
    unconditional_recursion,
    unused,
    unused_allocation,
    unused_comparisons,
    unused_parens,
    while_true,
    missing_debug_implementations,
    //TODO: activate this!
    //missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    missing_copy_implementations,
    rustdoc::broken_intra_doc_links,
)]
#![allow(clippy::multiple_crate_versions)]
//! # TSS 2.0 Rust Wrapper over Enhanced System API
//! This crate exposes the functionality of the TCG Software Stack Enhanced System API to
//! Rust developers, both directly through FFI bindings and through more Rust-tailored interfaces
//! at varying levels of abstraction.
//! Only platforms based on processors with a word size of at least 16 bits are supported.
//!
//! # Relevant specifications
//! This library is built with insight from Trusted Computing Group specifications. The specs most relevant
//! here are:
//! * the [Trusted Platform Module Library Specification, Family “2.0”, Level 00, Revision 01.59](https://trustedcomputinggroup.org/work-groups/trusted-platform-module/)
//! * the [TCG TSS 2.0 Enhanced System API (ESAPI) Specification, version 1.00, revision 14](https://trustedcomputinggroup.org/resource/tcg-tss-2-0-enhanced-system-api-esapi-specification/)
//!
//! The different parts of the first spec mentioned above (henceforth called the TPM2 spec) can be
//! referenced individually throughout the documentation of this crate, using their part number or name.
//! For example,
//! [Part 1, Architecture](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf)
//! could be referenced as "the Architecture spec" or "part 1 of the TPM2 spec".
//!
//! The second spec mentioned above will henceforth be called the ESAPI or ESys spec.
//!
//! Some parts of the code relate to features or functionality defined in other specifications (such as the
//! [Marshaling/Unmarshaling API v1, rev7 spec](https://trustedcomputinggroup.org/resource/tcg-tss-2-0-marshalingunmarshaling-api-specification/)),
//! and in such cases the specification should be linked and referenced in full.
//!
//! # Code structure
//! Our code structure is mostly derived from part 2 of the TPM2 spec.
//! For simplicity, however, we have reduced the depth of the import tree, so most (if not all) types
//! are at most one level away from root.
//!
//! Minimum supported Rust version (MSRV):
//! We currently check with version 1.66.0 of the Rust compiler during CI builds.
//!
//! # Notes on code safety:
//! * thread safety is ensured by the required mutability of the `Context` structure within the
//!   methods implemented on it; thus, in an otherwise safe app commands cannot be dispatched in
//!   parallel for the same context; whether multithreading with multiple context objects is possible
//!   depends on the TCTI used and this is the responsibility of the crate client to establish.
//! * the `unsafe` keyword is used to denote methods that could panic, crash or cause undefined
//!   behaviour. Whenever this is the case, the properties that need to be checked against
//!   parameters before passing them in will be stated in the documentation of the method.
//! * `unsafe` blocks within this crate need to be documented through code comments if they
//!   are not covered by the points of trust described here.
//! * the TSS2.0 library that this crate links to is trusted to return consistent values and to
//!   not crash or lead to undefined behaviour when presented with valid arguments.
//! * the `Mbox` crate is trusted to perform operations safely on the pointers provided to it, if
//!   the pointers are trusted to be valid.
//! * methods not marked `unsafe` are trusted to behave safely, potentially returning appropriate
//!   error messages when encountering any problems.
//! * whenever `unwrap`, `expect`, `panic` or derivatives of these are used, they need to be
//!   thoroughly documented and justified - preferably `unwrap` and `expect` should *never* fail
//!   during normal operation.
//! * these rules can be broken in test-only code and in tests.
//!
//! # Logging
//! This crate uses the typical `log` crate for printing errors generated in method calls. If
//! you would like to filter out these log messages, please check with your logger documentation
//! on how to do that.
//!
//! Additionally, the TSS library will also generate its own log messages and these can be
//! controlled through environment variables as explained
//! [here](https://github.com/tpm2-software/tpm2-tss/blob/main/doc/logging.md#runtime-log-level).
//!
pub use abstraction::transient::TransientKeyContext;
pub use context::Context;
pub use error::{Error, Result, WrapperErrorKind};
pub use tcti_ldr::TctiNameConf;
// To replace painlessly the old Tcti structure, should maybe be deprecated at some point.
pub use tcti_ldr::TctiNameConf as Tcti;

pub use tss_esapi_sys as tss2_esys;
pub mod abstraction;
pub mod attributes;
pub mod constants;
mod context;
mod error;
pub mod handles;
pub mod interface_types;
pub mod structures;
pub mod tcti_ldr;
pub mod traits;
pub mod utils;
