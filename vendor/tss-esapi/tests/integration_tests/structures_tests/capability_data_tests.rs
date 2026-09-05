// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::constants::CapabilityType;
use tss_esapi::structures::CapabilityData;

use crate::common::create_ctx_without_session;

#[test]
fn test_algorithms() {
    let mut context = create_ctx_without_session();

    let (capabs, _more) = context
        .get_capability(CapabilityType::Algorithms, 0, 80)
        .unwrap();

    if let CapabilityData::Algorithms(list) = capabs {
        assert!(!list.is_empty());
    } else {
        panic!("Got wrong type of capability data: {:?}", capabs);
    }
}

#[test]
fn test_handles() {
    let mut context = create_ctx_without_session();

    let (capabs, _more) = context
        .get_capability(CapabilityType::Handles, 0, 80)
        .unwrap();

    if let CapabilityData::Handles(vec) = capabs {
        assert!(!vec.is_empty());
    } else {
        panic!("Got wrong type of capability data: {:?}", capabs);
    }
}

#[test]
fn test_command() {
    let mut context = create_ctx_without_session();

    let (capabs, _more) = context
        .get_capability(CapabilityType::Command, 0, 80)
        .unwrap();

    if let CapabilityData::Commands(vec) = capabs {
        assert!(!vec.is_empty());
    } else {
        panic!("Got wrong type of capability data: {:?}", capabs);
    }
}

#[test]
fn test_pp_commands() {
    let mut context = create_ctx_without_session();

    let (capabs, _more) = context
        .get_capability(CapabilityType::PpCommands, 0, 80)
        .unwrap();

    if let CapabilityData::PpCommands(list) = capabs {
        assert!(!list.is_empty());
    } else {
        panic!("Got wrong type of capability data: {:?}", capabs);
    }
}

#[test]
fn test_audit_commands() {
    let mut context = create_ctx_without_session();

    let (capabs, _more) = context
        .get_capability(CapabilityType::AuditCommands, 0, 80)
        .unwrap();

    if let CapabilityData::AuditCommands(list) = capabs {
        assert!(!list.is_empty());
    } else {
        panic!("Got wrong type of capability data: {:?}", capabs);
    }
}

#[test]
fn test_assigned_pcr() {
    let mut context = create_ctx_without_session();

    let (capabs, _more) = context
        .get_capability(CapabilityType::AssignedPcr, 0, 80)
        .unwrap();

    if let CapabilityData::AssignedPcr(list) = capabs {
        assert!(!list.is_empty());
    } else {
        panic!("Got wrong type of capability data: {:?}", capabs);
    }
}

#[test]
fn test_tpm_properties() {
    let mut context = create_ctx_without_session();

    let (capabs, _more) = context
        .get_capability(CapabilityType::TpmProperties, 0, 80)
        .unwrap();

    if let CapabilityData::TpmProperties(list) = capabs {
        assert!(!list.is_empty());
    } else {
        panic!("Got wrong type of capability data: {:?}", capabs);
    }
}

#[test]
fn test_pcr_properties() {
    let mut context = create_ctx_without_session();

    let (capabs, _more) = context
        .get_capability(CapabilityType::PcrProperties, 0, 80)
        .unwrap();

    if let CapabilityData::PcrProperties(list) = capabs {
        assert!(!list.is_empty());
    } else {
        panic!("Got wrong type of capability data: {:?}", capabs);
    }
}

#[test]
fn test_ecc_curves() {
    let mut context = create_ctx_without_session();

    let (capabs, _more) = context
        .get_capability(CapabilityType::EccCurves, 0, 80)
        .unwrap();

    if let CapabilityData::EccCurves(vec) = capabs {
        assert!(!vec.is_empty());
    } else {
        panic!("Got wrong type of capability data: {:?}", capabs);
    }
}

// For these tests to work the tpm2-tss library need to have the
// authPolicies field in the TPMU_CAPABILITIES union.
// #[test]
// fn test_auth_policies() {
//     let mut context = create_ctx_without_session();

//     let (capabs, _more) = context
//         .get_capability(CapabilityType::AuthPolicies, 0, 80)
//         .unwrap();

//     if let CapabilityData::AuthPolicies(list) = capabs {
//         assert!(!list.is_empty());
//     } else {
//         panic!("Got wrong type of capability data: {:?}", capabs);
//     }
// }

// For these tests to work the tpm2-tss library need to have the
// actData field in the TPMU_CAPABILITIES union.
// #[test]
// fn test_act() {
//     let mut context = create_ctx_without_session();

//     let (capabs, _more) = context.get_capability(CapabilityType::Act, 0, 80).unwrap();

//     if let CapabilityData::ActData(list) = capabs {
//         assert!(!list.is_empty());
//     } else {
//         panic!("Got wrong type of capability data: {:?}", capabs);
//     }
// }
