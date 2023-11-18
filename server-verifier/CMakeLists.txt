# Build for Linux
set(CMAKE_C_COMPILER /usr/bin/gcc)
set(CMAKE_CXX_COMPILER /usr/bin/g++)
set(CMAKE_ASM_COMPILER /usr/bin/gcc)
set(CMAKE_LINKER /usr/bin/ld)

set(host_bin server-verifier)
set(host_src host/host.c)

# host
add_executable(${host_bin} ${host_src} host/net.h custom_certs.c custom_certs.h)
target_link_libraries(${host_bin} ${MBEDTLS_LIB_TLS_HOST_LINUX} ${MBEDTLS_LIB_X509_HOST_LINUX} ${MBEDTLS_LIB_CRYPTO_HOST_LINUX})
target_include_directories(${host_bin} 
  PRIVATE ${MBEDTLS_DIR_HOST}/include 
  PRIVATE .)
