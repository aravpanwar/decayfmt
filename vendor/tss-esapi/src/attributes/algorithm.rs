// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::tss2_esys::TPMA_ALGORITHM;
use bitfield::bitfield;

bitfield! {
    /// Bitfield representing the algorithm attributes.
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct AlgorithmAttributes(TPMA_ALGORITHM);
    impl Debug;

    pub asymmetric, _: 0;
    pub symmetric, _: 1;
    pub hash, _: 2;
    pub object, _: 3;
    // 7:4 Reserved
    pub signing, _: 8;
    pub encrypting, _: 9;
    pub method, _: 10;
    // 31:11 Reserved
}

impl From<TPMA_ALGORITHM> for AlgorithmAttributes {
    fn from(tpma_algorithm: TPMA_ALGORITHM) -> Self {
        AlgorithmAttributes(tpma_algorithm)
    }
}

impl From<AlgorithmAttributes> for TPMA_ALGORITHM {
    fn from(algorithm_attributes: AlgorithmAttributes) -> Self {
        algorithm_attributes.0
    }
}
