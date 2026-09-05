#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -euf -o pipefail

#################################
# Run the TPM simulation server #
#################################
tpm_server &
sleep 5
tpm2_startup -c -T mssim

#############################
# Install and run tarpaulin #
#############################
cargo install cargo-tarpaulin
cargo tarpaulin --tests --out Xml --exclude-files="tests/*,../*" -- --test-threads=1 --nocapture
