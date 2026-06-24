#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG="${1:-Release}"
BUILD_DIR="build-mingw-${CONFIG,,}"

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

cmake .. -G Ninja \
  -DCMAKE_BUILD_TYPE="${CONFIG}" \
  -DCMAKE_TOOLCHAIN_FILE=../scripts/mingw-x86_64-w64.cmake

cmake --build .
