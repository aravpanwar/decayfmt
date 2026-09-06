#!/usr/bin/env bash

# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Cross compile the `tss-esapi` crate (and its dependencies) for Armv7 and Aarch64
# In order to cross-compile the TSS library we need to also cross-compile OpenSSL

set -euf -o pipefail

OPENSSL_GIT="https://github.com/openssl/openssl.git"
OPENSSL_VERSION="OpenSSL_1_1_1j"
TPM2_TSS_GIT="https://github.com/tpm2-software/tpm2-tss.git"
TPM2_TSS_VERSION="2.4.6"

export SYSROOT="/tmp/sysroot"

git_checkout() {
    if [ ! -d "/tmp/$(basename "$1" ".git")" ]; then
	pushd /tmp
	git clone "$1" --branch "$2"
	popd
    fi
}

prepare_sysroot() {
    # Prepare the SYSROOT
    [ -d "$SYSROOT" ] && rm -fr "$SYSROOT"
    mkdir -p "$SYSROOT"

    # Allow the `pkg-config` crate to cross-compile
    export PKG_CONFIG_ALLOW_CROSS=1
    export PKG_CONFIG_PATH="$SYSROOT"/lib/pkgconfig:"$SYSROOT"/share/pkgconfig
    export PKG_CONFIG_SYSROOT_DIR="$SYSROOT"
}

cross-compile-openssl() {
    pushd /tmp/openssl
    # Compile and copy files over
    ./Configure $2 shared --prefix="$SYSROOT" --openssldir="$SYSROOT"/openssl --cross-compile-prefix=$1-
    make clean
    make depend
    make -j$(nproc)
    make install_sw
    popd
}

cross-compile-tpm2-tss() {
    pushd /tmp/tpm2-tss
    [ ! -f configure ] && ./bootstrap
    ./configure --enable-fapi=no --prefix=/ --build=x86_64-pc-linux-gnu --host=$1 --target=$1 CC=$1-gcc
    make clean
    make -j$(nproc)
    make DESTDIR="$SYSROOT" install
    popd
}

# Download cross-compilers
apt update
apt install -y gcc-multilib
apt install -y gcc-arm-linux-gnueabi
apt install -y gcc-aarch64-linux-gnu

# Download other dependencies
apt install -y autoconf
apt install -y autoconf-archive
apt install -y cmake
apt install -y libclang-dev
apt install -y libtool
apt install -y pkgconf

# Download OpenSSL, tpm2-tss and dependencies source code
git_checkout "$OPENSSL_GIT" "$OPENSSL_VERSION"
git_checkout "$TPM2_TSS_GIT" "$TPM2_TSS_VERSION"

# Download OpenSSL source code
if [ ! -d "/tmp/openssl" ]; then
    pushd /tmp
    git clone https://github.com/openssl/openssl.git --branch $OPENSSL_VERSION
    popd
fi

# Clean and prepare SYSROOT
prepare_sysroot

# Compile OpenSSL and TSS stack for aarch64-unknown-linux-gnu
cross-compile-openssl aarch64-linux-gnu linux-generic64
cross-compile-tpm2-tss aarch64-linux-gnu

rustup target add aarch64-unknown-linux-gnu
cargo build --features generate-bindings --target aarch64-unknown-linux-gnu
cargo build --target aarch64-unknown-linux-gnu

# Clean and prepare SYSROOT
prepare_sysroot

# Compile OpenSSL and TSS stack for armv7-unknown-linux-gnueabi
cross-compile-openssl arm-linux-gnueabi linux-generic32
cross-compile-tpm2-tss arm-linux-gnueabi

rustup target add armv7-unknown-linux-gnueabi
cargo build --features generate-bindings --target armv7-unknown-linux-gnueabi
cargo build --target armv7-unknown-linux-gnueabi
