// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    if let Ok(tss2_esys_version) = std::env::var("DEP_TSS2_ESYS_VERSION") {
        match tss2_esys_version.chars().next().unwrap() {
            '2' => println!("cargo:rustc-cfg=tpm2_tss_version=\"2\""),
            '3' => println!("cargo:rustc-cfg=tpm2_tss_version=\"3\""),
            '4' => println!("cargo:rustc-cfg=tpm2_tss_version=\"4\""),
            major => panic!("Unsupported TSS version: {}", major),
        }
    }
}
