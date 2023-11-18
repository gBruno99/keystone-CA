#!/bin/bash

set -e

cd ../mbedtls_builds/mbedtls_eapp/
git add -N include/mbedtls/ed25519.h
git add -N include/mbedtls/keystone_ext.h
git add -N include/mbedtls/print.h
git add -N include/mbedtls/sha3.h
git add -N library/ed25519.c
git add -N library/print.c
git add -N library/sha3.c
git add -N library/ed25519
git add -N library/verifier_utils_mock
git diff > mbedtls_eapp.patch
cp mbedtls_eapp.patch ../../patches/
git add .
git restore --staged .

cd ../mbedtls_host/
git add -N include/mbedtls/ed25519.h
git add -N include/mbedtls/keystone_ext.h
git add -N include/mbedtls/print.h
git add -N include/mbedtls/sha3.h
git add -N library/ed25519.c
git add -N library/print.c
git add -N library/sha3.c
git add -N library/ed25519
git add -N library/verifier_utils_mock
git diff > mbedtls_host.patch
cp mbedtls_host.patch ../../patches/
git add .
git restore --staged .
