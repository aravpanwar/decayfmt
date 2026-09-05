// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::traits::{Marshall, UnMarshall};

pub fn check_marshall_unmarshall<T: Marshall + UnMarshall + Eq + std::fmt::Debug>(val: &T) {
    let buf = val.marshall().expect("Failed to marshall value");

    let unmarshalled = T::unmarshall(&buf).expect("Failed to unmarshall");

    assert_eq!(val, &unmarshalled);
}
