// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "generate-bindings")]
use std::path::PathBuf;

const MINIMUM_VERSION: &str = "2.4.6";

fn main() {
    if std::env::var("DOCS_RS").is_ok() {
        // Nothing to be done for docs.rs builds.
        return;
    }

    #[cfg(feature = "generate-bindings")]
    {
        let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let esys_path = out_path.join("tss_esapi_bindings.rs");
        generate_from_system(esys_path);
    }

    #[cfg(not(feature = "generate-bindings"))]
    {
        use std::str::FromStr;
        use target_lexicon::{Architecture, OperatingSystem, Triple};

        let target = Triple::from_str(&std::env::var("TARGET").unwrap())
            .expect("Failed to parse target triple");
        match (target.architecture, target.operating_system) {
            (Architecture::Arm(_), OperatingSystem::Linux) => {}
            (Architecture::Aarch64(_), OperatingSystem::Linux) => {}
            (Architecture::X86_64, OperatingSystem::Darwin) => {}
            (Architecture::X86_64, OperatingSystem::Linux) => {}
            (arch, os) => {
                panic!("Compilation target (architecture, OS) tuple ({}, {}) is not part of the supported tuples. Please compile with the \"generate-bindings\" feature or add support for your platform :)", arch, os);
            }
        }

        pkg_config::Config::new()
            .atleast_version(MINIMUM_VERSION)
            .probe("tss2-sys")
            .expect("Failed to find tss2-sys library.");
        let tss2_esys = pkg_config::Config::new()
            .atleast_version(MINIMUM_VERSION)
            .probe("tss2-esys")
            .expect("Failed to find tss2-esys library.");
        pkg_config::Config::new()
            .atleast_version(MINIMUM_VERSION)
            .probe("tss2-tctildr")
            .expect("Failed to find tss2-tctildr library.");
        pkg_config::Config::new()
            .atleast_version(MINIMUM_VERSION)
            .probe("tss2-mu")
            .expect("Failed to find tss2-mu library.");

        println!("cargo:version={}", tss2_esys.version);
    }
}

#[cfg(feature = "generate-bindings")]
pub fn generate_from_system(esapi_out: PathBuf) {
    pkg_config::Config::new()
        .atleast_version(MINIMUM_VERSION)
        .probe("tss2-sys")
        .expect("Failed to find tss2-sys library.");
    let tss2_esys = pkg_config::Config::new()
        .atleast_version(MINIMUM_VERSION)
        .probe("tss2-esys")
        .expect("Failed to find tss2-esys");
    let tss2_tctildr = pkg_config::Config::new()
        .atleast_version(MINIMUM_VERSION)
        .probe("tss2-tctildr")
        .expect("Failed to find tss2-tctildr");
    let tss2_mu = pkg_config::Config::new()
        .atleast_version(MINIMUM_VERSION)
        .probe("tss2-mu")
        .expect("Failed to find tss2-mu");

    println!("cargo:version={}", tss2_esys.version);

    // These three pkg-config files should contain only one include/lib path.
    let tss2_esys_include_path = tss2_esys.include_paths[0]
        .clone()
        .into_os_string()
        .into_string()
        .expect("Error converting OsString to String.");
    let tss2_tctildr_include_path = tss2_tctildr.include_paths[0]
        .clone()
        .into_os_string()
        .into_string()
        .expect("Error converting OsString to String.");
    let tss2_mu_include_path = tss2_mu.include_paths[0]
        .clone()
        .into_os_string()
        .into_string()
        .expect("Error converting OsString to String.");

    bindgen::Builder::default()
        .size_t_is_usize(false)
        .clang_arg(format!("-I{}/tss2/", tss2_esys_include_path))
        .clang_arg(format!("-I{}/tss2/", tss2_tctildr_include_path))
        .clang_arg(format!("-I{}/tss2/", tss2_mu_include_path))
        .header(format!("{}/tss2/tss2_esys.h", tss2_esys_include_path))
        .header(format!("{}/tss2/tss2_tctildr.h", tss2_tctildr_include_path))
        .header(format!("{}/tss2/tss2_mu.h", tss2_mu_include_path))
        // See this issue: https://github.com/parallaxsecond/rust-cryptoki/issues/12
        .blocklist_type("max_align_t")
        .no_default(".*tagMONITORINFOEXA")
        .generate_comments(false)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings to TSS2 ESYS APIs.")
        .write_to_file(esapi_out)
        .expect("Couldn't write ESYS bindings!");
}
