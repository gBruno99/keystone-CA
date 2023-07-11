set(eapp_bin tls-client-enclave)
set(eapp_src eapp/hello.c)
set(host_bin tls-client-enclave-runner)
set(host_src host/host.cpp)
set(package_name "tls-client-enclave.ke")
set(package_script "./tls-client-enclave-runner tls-client-enclave eyrie-rt")

if(RISCV32)
  set(eyrie_plugins "freemem io_syscall linux_syscall env_setup rv32")
else()
  set(eyrie_plugins "freemem io_syscall linux_syscall env_setup")
endif()

# eapp

add_executable(${eapp_bin} ${eapp_src} certs.c certs.h)
target_link_libraries(${eapp_bin} "-static" ${MBEDTLS_LIB_TLS_HOST} ${MBEDTLS_LIB_X509_HOST} ${MBEDTLS_LIB_CRYPTO_HOST})
target_include_directories(${eapp_bin} PRIVATE ${MBEDTLS_DIR_HOST}/include PRIVATE .)

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

