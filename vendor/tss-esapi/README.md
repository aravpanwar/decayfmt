# TPM2 Software Stack Rust Wrapper 

<p align="center">
  <a href="https://crates.io/crates/tss-esapi"><img alt="Crates.io" src="https://img.shields.io/crates/v/tss-esapi"></a>
  <a href="https://docs.rs/tss-esapi"><img src="https://docs.rs/tss-esapi/badge.svg" alt="Code documentation"/></a>
  <a href="https://codecov.io/gh/parallaxsecond/rust-tss-esapi"><img src="https://codecov.io/gh/parallaxsecond/rust-tss-esapi/branch/main/graph/badge.svg?token=5T7SVCHWFE"/></a>
</p>

This is the high-level, Rust idiomatic wrapper crate that exposes an interface 
to [TSS](https://github.com/tpm2-software/tpm2-tss).

This crate depends on the [`tss-esapi-sys`](../tss-esapi-sys/) crate for its
FFI interface. By default, pre-generated bindings are used. If you'd like the
bindings to be generated at build time, please enable either the 
`generate-bindings` feature - the FFI bindings will then be generated at build
time using the headers identified on the system.

Our end-goal is to achieve a fully Rust-native interface that offers strong safety and security guarantees. Check out our [documentation](https://docs.rs/tss-esapi/*/tss_esapi/#notes-on-code-safety) for an overview of our code safety approach.

## Cross compiling

For more information on cross-compiling the `tss-esapi` crate, please see the README of the `tss-esapi-sys` crate.

*Copyright 2021 Contributors to the Parsec project.*
