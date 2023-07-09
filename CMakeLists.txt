cmake_minimum_required(VERSION 3.10)
enable_language(C CXX ASM)

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()
set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

if (NOT DEFINED ENV{MBEDTLS_DIR_EAPP})
  message(FATAL_ERROR "Please set MBEDTLS_DIR_EAPP")
endif()
set(MBEDTLS_DIR_EAPP $ENV{MBEDTLS_DIR_EAPP})

if (NOT DEFINED ENV{MBEDTLS_DIR_HOST})
  message(FATAL_ERROR "Please set MBEDTLS_DIR_HOST")
endif()
set(MBEDTLS_DIR_HOST $ENV{MBEDTLS_DIR_HOST})

if (NOT DEFINED ENV{OPENSSL_DIR})
  message(FATAL_ERROR "Please set OPENSSL_DIR")
endif()
set(OPENSSL_DIR $ENV{OPENSSL_DIR})

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

if(RISCV32)
  message(STATUS "riscv32")
  set(BITS 32)
else()
  message(STATUS "riscv64")
  set(BITS 64)
endif()

use_riscv_toolchain(${BITS})

# export include directory
include_directories(include
  ${KEYSTONE_SDK_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/host
  ${KEYSTONE_SDK_DIR}/include/edge
  ${KEYSTONE_SDK_DIR}/include/verifier)

# set paths to the libraries
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)

set(MBEDTLS_LIB_CRYPTO_EAPP ${MBEDTLS_DIR_EAPP}/build/library/libmbedcrypto.a)
set(MBEDTLS_LIB_TLS_EAPP ${MBEDTLS_DIR_EAPP}/build/library/libmbedtls.a)
set(MBEDTLS_LIB_X509_EAPP ${MBEDTLS_DIR_EAPP}/build/library/libmbedx509.a)

set(MBEDTLS_LIB_CRYPTO_HOST ${MBEDTLS_DIR_HOST}/build/library/libmbedcrypto.a)
set(MBEDTLS_LIB_TLS_HOST ${MBEDTLS_DIR_HOST}/build/library/libmbedtls.a)
set(MBEDTLS_LIB_X509_HOST ${MBEDTLS_DIR_HOST}/build/library/libmbedx509.a)

set(OPENSSL_LIB_SSL ${OPENSSL_DIR}/lib/libssl.a)
set(OPENSSL_LIB_CRYPTO ${OPENSSL_DIR}/lib/libcrypto.a)

# find program "makeself"
find_program(MAKESELF makeself)

# enclave
# add_subdirectory(client)
add_subdirectory(hello)
add_subdirectory(hello-native)
add_subdirectory(enclave-client)

