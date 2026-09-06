#!/usr/bin/env bash

# Copyright 2019 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# This script executes tests for the tss-esapi crate.
# It can be run inside the container which Dockerfile is in the same folder.
#
# Usage: ./tests/all.sh

set -euf -o pipefail

if [[ ! -z ${USE_FROZEN_LOCKFILE:+x} ]]; then
	# Some versions of Fedora that are used during testing are old
    # so in order to prevent any drift from the versions available
    # in the old versions the frozen Cargo lock is used.
	cp tests/Cargo.lock.frozen ../Cargo.lock
fi

############################
# Run the TPM SWTPM server #
############################
mkdir -p /tmp/tpmdir
swtpm_setup --tpm2 \
    --tpmstate /tmp/tpmdir \
    --createek --decryption --create-ek-cert \
    --create-platform-cert \
    --pcr-banks sha1,sha256 \
    --display
swtpm socket --tpm2 \
    --tpmstate dir=/tmp/tpmdir \
    --flags startup-clear \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --daemon
tpm2-abrmd \
    --logger=stdout \
    --tcti=swtpm: \
    --allow-root \
    --session \
    --flush-all &

###################
# Build the crate #
###################
RUST_BACKTRACE=1 cargo build --features generate-bindings

#################
# Run the tests #
#################
TEST_TCTI=tabrmd:bus_type=session RUST_BACKTRACE=1 RUST_LOG=info cargo test --features generate-bindings --  --test-threads=1 --nocapture
