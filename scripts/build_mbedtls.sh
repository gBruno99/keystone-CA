#!/bin/bash

set -e

cd ../mbedtls_builds/mbedtls_eapp/build
cmake -DCMAKE_TOOLCHAIN_FILE=$DEMO_DIR/riscv-toolchain.cmake -DENABLE_TESTING=0ff ..
cmake --build .

cd ../../mbedtls_host/build_riscv
cmake -DCMAKE_TOOLCHAIN_FILE=$DEMO_DIR/riscv-toolchain.cmake -DENABLE_TESTING=0ff ..
cmake --build .
cd ../build_linux
cmake  -DENABLE_TESTING=0ff ..
cmake --build .