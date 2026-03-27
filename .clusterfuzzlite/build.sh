#!/bin/bash -eu

# Install build dependencies required by vendored vectorscan (C/C++)
apt-get update -qq
apt-get install -y --no-install-recommends \
    cmake pkg-config libboost-dev patch ragel

cd "$SRC/kingfisher"

# OSS-Fuzz's clang/libc++ toolchain builds vendored Vectorscan against Ubuntu
# 20.04's Boost headers. Re-enable the removed unary_function/binary_function
# compatibility shims so Boost 1.71 still compiles in C++17 mode.
export CXXFLAGS="${CXXFLAGS:-} -D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION"

# Build all fuzz targets in release mode with debug assertions
cargo fuzz build -O --debug-assertions

# Copy built fuzz binaries to the output directory
FUZZ_TARGET_OUTPUT_DIR=fuzz/target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs; do
    FUZZ_TARGET_NAME=$(basename "${f%.*}")
    if [ -f "$FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME" ]; then
        cp "$FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME" "$OUT/"
    fi
done
