// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::tcti_ldr::TctiContext;

#[test]
fn new_context() {
    let _context = TctiContext::initialize(crate::tcti_ldr_tests::name_conf()).unwrap();
}
