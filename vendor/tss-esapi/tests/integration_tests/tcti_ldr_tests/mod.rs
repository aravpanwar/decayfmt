// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::str::FromStr;
use tss_esapi::tcti_ldr::TctiNameConf;

#[allow(dead_code)]
pub fn name_conf() -> TctiNameConf {
    match env::var("TEST_TCTI") {
        Err(_) => TctiNameConf::Mssim(Default::default()),
        Ok(tctistr) => TctiNameConf::from_str(&tctistr).expect("Error parsing TEST_TCTI"),
    }
}

mod tcti_context_tests;
mod tcti_info_tests;
