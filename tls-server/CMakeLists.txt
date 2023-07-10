set(host_bin tls-server.riscv)
set(host_src host/host.c)

# host

add_executable(${host_bin} ${host_src} certs.c certs.h)
target_link_libraries(${host_bin} ${MBEDTLS_LIB_TLS_HOST} ${MBEDTLS_LIB_X509_HOST} ${MBEDTLS_LIB_CRYPTO_HOST})
target_include_directories(${host_bin} PRIVATE ${MBEDTLS_DIR_HOST}/include PRIVATE .)


