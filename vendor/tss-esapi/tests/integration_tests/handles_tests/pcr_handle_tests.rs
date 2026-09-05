// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::{From, TryFrom};
use tss_esapi::{
    handles::{ObjectHandle, PcrHandle},
    tss2_esys::{
        ESYS_TR, ESYS_TR_PCR0, ESYS_TR_PCR1, ESYS_TR_PCR10, ESYS_TR_PCR11, ESYS_TR_PCR12,
        ESYS_TR_PCR13, ESYS_TR_PCR14, ESYS_TR_PCR15, ESYS_TR_PCR16, ESYS_TR_PCR17, ESYS_TR_PCR18,
        ESYS_TR_PCR19, ESYS_TR_PCR2, ESYS_TR_PCR20, ESYS_TR_PCR21, ESYS_TR_PCR22, ESYS_TR_PCR23,
        ESYS_TR_PCR24, ESYS_TR_PCR25, ESYS_TR_PCR26, ESYS_TR_PCR27, ESYS_TR_PCR28, ESYS_TR_PCR29,
        ESYS_TR_PCR3, ESYS_TR_PCR30, ESYS_TR_PCR31, ESYS_TR_PCR4, ESYS_TR_PCR5, ESYS_TR_PCR6,
        ESYS_TR_PCR7, ESYS_TR_PCR8, ESYS_TR_PCR9,
    },
};

#[test]
fn test_conversion_of_invalid_handle() {
    let invalid_value: ESYS_TR = 0xFFFFFFFF;
    let invalid_object_handle: ObjectHandle = ObjectHandle::from(invalid_value);
    let _ = PcrHandle::try_from(invalid_value).unwrap_err();
    let _ = PcrHandle::try_from(invalid_object_handle).unwrap_err();
}

macro_rules! test_valid_conversions {
    ($esys_tr_handle:ident, PcrHandle::$pcr_handle:ident) => {
        assert_eq!(
            ObjectHandle::from(PcrHandle::$pcr_handle),
            ObjectHandle::from($esys_tr_handle),
            "ObjectHandle conversion failed for PcrHandle::{}",
            std::stringify!($pcr_handle)
        );

        assert_eq!(
            $esys_tr_handle,
            ESYS_TR::from(PcrHandle::$pcr_handle),
            "Esys TR handle conversion failed for PcrHandle::{}",
            std::stringify!($pcr_handle),
        );

        assert_eq!(
            PcrHandle::$pcr_handle,
            PcrHandle::try_from($esys_tr_handle).expect(&format!(
                "Failed to convert {} to PcrHandle",
                std::stringify!($esys_tr_handle)
            )),
            "{} did not convert to the expected value PcrHandle::{}",
            std::stringify!($esys_tr_handle),
            std::stringify!($pcr_handle),
        );
    };
}

#[test]
fn test_conversion_of_valid_handle() {
    // Check the valid values
    test_valid_conversions!(ESYS_TR_PCR0, PcrHandle::Pcr0);
    test_valid_conversions!(ESYS_TR_PCR1, PcrHandle::Pcr1);
    test_valid_conversions!(ESYS_TR_PCR2, PcrHandle::Pcr2);
    test_valid_conversions!(ESYS_TR_PCR3, PcrHandle::Pcr3);
    test_valid_conversions!(ESYS_TR_PCR4, PcrHandle::Pcr4);
    test_valid_conversions!(ESYS_TR_PCR5, PcrHandle::Pcr5);
    test_valid_conversions!(ESYS_TR_PCR6, PcrHandle::Pcr6);
    test_valid_conversions!(ESYS_TR_PCR7, PcrHandle::Pcr7);
    test_valid_conversions!(ESYS_TR_PCR8, PcrHandle::Pcr8);
    test_valid_conversions!(ESYS_TR_PCR9, PcrHandle::Pcr9);
    test_valid_conversions!(ESYS_TR_PCR10, PcrHandle::Pcr10);
    test_valid_conversions!(ESYS_TR_PCR11, PcrHandle::Pcr11);
    test_valid_conversions!(ESYS_TR_PCR12, PcrHandle::Pcr12);
    test_valid_conversions!(ESYS_TR_PCR13, PcrHandle::Pcr13);
    test_valid_conversions!(ESYS_TR_PCR14, PcrHandle::Pcr14);
    test_valid_conversions!(ESYS_TR_PCR15, PcrHandle::Pcr15);
    test_valid_conversions!(ESYS_TR_PCR16, PcrHandle::Pcr16);
    test_valid_conversions!(ESYS_TR_PCR17, PcrHandle::Pcr17);
    test_valid_conversions!(ESYS_TR_PCR18, PcrHandle::Pcr18);
    test_valid_conversions!(ESYS_TR_PCR19, PcrHandle::Pcr19);
    test_valid_conversions!(ESYS_TR_PCR20, PcrHandle::Pcr20);
    test_valid_conversions!(ESYS_TR_PCR21, PcrHandle::Pcr21);
    test_valid_conversions!(ESYS_TR_PCR22, PcrHandle::Pcr22);
    test_valid_conversions!(ESYS_TR_PCR23, PcrHandle::Pcr23);
    test_valid_conversions!(ESYS_TR_PCR24, PcrHandle::Pcr24);
    test_valid_conversions!(ESYS_TR_PCR25, PcrHandle::Pcr25);
    test_valid_conversions!(ESYS_TR_PCR26, PcrHandle::Pcr26);
    test_valid_conversions!(ESYS_TR_PCR27, PcrHandle::Pcr27);
    test_valid_conversions!(ESYS_TR_PCR28, PcrHandle::Pcr28);
    test_valid_conversions!(ESYS_TR_PCR29, PcrHandle::Pcr29);
    test_valid_conversions!(ESYS_TR_PCR30, PcrHandle::Pcr30);
    test_valid_conversions!(ESYS_TR_PCR31, PcrHandle::Pcr31);
}
