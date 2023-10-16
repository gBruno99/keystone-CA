#!/bin/bash

cd ./scripts 
KEYSTONE_BUILD_DIR=../../keystone/build ./get_attestation.sh ../mbedtls_builds/mbedtls_host/library/verifier_utils_mock/
cd ../mbedtls_builds/mbedtls_host/build_riscv/
cmake -DCMAKE_TOOLCHAIN_FILE=$DEMO_DIR/riscv-toolchain.cmake -DENABLE_TESTING=0ff ..
cmake --build .
cd ../build_linux
cmake  -DENABLE_TESTING=0ff ..
cmake --build .