cmake_minimum_required(VERSION 3.10)
enable_language(C CXX ASM)

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()
set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

if (NOT DEFINED ENV{MBEDTLS_DIR})
  message(FATAL_ERROR "Please set MBEDTLS_DIR")
endif()
set(MBEDTLS_DIR $ENV{MBEDTLS_DIR})

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
  ${MBEDTLS_DIR}/include
  ${KEYSTONE_SDK_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/host
  ${KEYSTONE_SDK_DIR}/include/edge
  ${KEYSTONE_SDK_DIR}/include/verifier)

# set paths to the libraries
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)

set(MBEDTLS_LIB_CRYPTO ${MBEDTLS_DIR}/build/library/libmbedcrypto.a)
set(MBEDTLS_LIB_TLS ${MBEDTLS_DIR}/build/library/libmbedtls.a)
set(MBEDTLS_LIB_X509 ${MBEDTLS_DIR}/build/library/libmbedx509.a)

# find program "makeself"
find_program(MAKESELF makeself)

# enclave
add_subdirectory(client)
add_subdirectory(hello)


