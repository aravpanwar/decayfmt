// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::tcti_ldr::TctiInfo;

#[test]
fn new_info() {
    let info = TctiInfo::get_info(crate::tcti_ldr_tests::name_conf()).unwrap();
    let _version = info.version();
    let _name = info.name();
    let _description = info.description();
    let _config_help = info.config_help();
}
