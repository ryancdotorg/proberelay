#!/bin/bash
# From https://gist.github.com/ryancdotorg/84275935f0b82578d8c222e2e915fc78
# built binaries at https://ryanc-musl-bins.s3.amazonaws.com/SHA256SUMS.html

set -eo pipefail
set -x

MUSL_DIR=/dev/shm/musl-cross
ORIG_PATH=$PATH

function setcross() {
    MUSL_CROSS=${1:-armv7l-linux-musleabihf}
    CROSS_BIN="$MUSL_DIR/$MUSL_CROSS-cross/bin"
    CROSS_PFX="$CROSS_BIN/$MUSL_CROSS"
    BIN_DIR="$OUTPUT_DIR/$MUSL_CROSS"

    if command -v _ccache > /dev/null; then
        export CC="ccache $CROSS_PFX-gcc"
        export CXX="ccache $CROSS_PFX-g++"
    else
        export CC=$CROSS_PFX-gcc
        export CXX=$CROSS_PFX-g++
    fi

    export AR=$CROSS_PFX-ar
    export AS=$CROSS_PFX-as
    export LD=$CROSS_PFX-ld
    export RANLIB=$CROSS_PFX-ranlib

    export PATH=$CROSS_BIN:$ORIG_PATH
    export STRIP="$CROSS_PFX-strip -s -R .comment -R .hash -R .gnu.hash -R .gnu.version --strip-unneeded"
    export LDFLAGS="-flto -Wl,--gc-sections"
    export CFLAGS="-flto -fno-inline-small-functions -ffunction-sections -fdata-sections -Wl,--gc-sections -static -Os"
    export CXXFLAGS="$CFLAGS"
    export MAKEFLAGS="-sj$((`grep -c '^processor' /proc/cpuinfo` * 125 / 100))"
}

function get_musl() {
    cd "$MUSL_DIR"

    HASHES="musl.SHA512SUMS"
    FLAGS="-L -o $HASHES"
    if [ -e "$HASHES" ]; then
        FLAGS="$FLAGS -z $HASHES"
    fi
    curl $FLAGS https://musl.cc/SHA512SUMS

    if [ ! -e "$MUSL_CROSS-cross.tgz" ]; then
        if [ -d "$MUSL_CROSS-cross" ]; then
           rm -rf "$MUSL_CROSS-cross"
        fi
        curl -LO "https://musl.cc/$MUSL_CROSS-cross.tgz"
    fi

    if (fgrep "$MUSL_CROSS-cross.tgz" "$HASHES" | sha512sum --strict --warn --status -c -); then
        if [ ! -d "$MUSL_CROSS-cross" ]; then
            tar -xzf "$MUSL_CROSS-cross.tgz"
        fi
    else
        rm "$MUSL_CROSS-cross.tgz"
        get_musl
    fi
}

function main() {
    HASH=$(sha256sum $0|head -c16)
    mkdir -p "$MUSL_DIR"
    ORIG_PWD="$PWD"
    setcross
    get_musl $MUSL_CROSS
    cd "$ORIG_PWD"
    exec "$@"
}

main "$@"
# vim:sw=4:ts=4:et:
