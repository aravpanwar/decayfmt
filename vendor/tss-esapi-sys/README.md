# TPM2 Software Stack Rust Wrapper

<p align="center">
  <a href="https://crates.io/crates/tss-esapi-sys"><img alt="Crates.io" src="https://img.shields.io/crates/v/tss-esapi-sys"></a>
  <a href="https://docs.rs/tss-esapi-sys"><img src="https://docs.rs/tss-esapi-sys/badge.svg" alt="Code documentation"/></a>
  <a href="https://codecov.io/gh/parallaxsecond/rust-tss-esapi"><img src="https://codecov.io/gh/parallaxsecond/rust-tss-esapi/branch/main/graph/badge.svg?token=5T7SVCHWFE"/></a>
</p>

This is the lower-level wrapper that exposes a minimal, low-level C
interface to Rust to [TSS](https://github.com/tpm2-software/tpm2-tss).

## Dependencies

This crate exposes an interface for the TSS Enhanced System API and thus
links to libraries that expose this interface. In order to allow proper use
of the ESAPI, this FFI layer includes bindings to TCTI and MU headers, and 
must therefore link to all of them at build time.

The paths to the libraries are discovered using `pkg-config` - make sure they
are discoverable in this way on your system. Our build script looks for 
`tss2-esys`, `tss2-tctildr` and `tss2-mu`. A minimum version of `2.3.3` is 
required for all of them.

Having installed the open-source implementation libraries at `/usr/local/lib` (by default), it
might happen that `pkg-config` can not find them. Run the following command if that is the
case:
```bash
$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

The FFI bindings presented by this crate can be either those commited in the
crate under `src/bindings` or generated on the fly from the library headers
found on the system, at build time. For generating the bindings at build time
please enable the `generate-bindings` feature, as it is not enabled by default.
The build script will then identify the header files using `pkg-config` and
generate fresh bindings from them.

NOTE: Only a limited set of bindings are committed and their target triplet
is included in the name of the file - if the triplet you require is not
available, feel free to raise a Pull Request to add it or to use build-time
generation of bindings. All the committed bindings **MUST** be generated from
the library version found under the `vendor` submodule.

## Cross compiling

Cross-compilation can be done as long as you have on your build system the TSS 
libraries compiled for your target system of choice. We rely on `pkg-config` to
identify the libraries which we link against. Installing `tpm2-tss` does yield
`.pc` files which can be used for this purpose, but depending on the exact build
environment setup, the configuration and compilation of `tpm2-tss` could require
some special tailoring.

We include cross-compilation builds as a nightly check in Github Actions - you
can find them
[here](https://github.com/parallaxsecond/rust-tss-esapi/blob/main/tss-esapi/tests/cross-compile.sh)
as an example of the steps needed. You can find more information on using
`pkg-config` when cross-compiling
[here](https://github.com/parallaxsecond/rust-tss-esapi/issues/204). Our
wrapper script around `pkg-config` can be seen
[here](https://github.com/parallaxsecond/rust-tss-esapi/blob/main/tss-esapi/tests/pkg-config).

Be advised that in some cases the linker used might need to be set manually in
`.cargo/config`.

*Copyright 2021 Contributors to the Parsec project.*
