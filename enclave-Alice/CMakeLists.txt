set(eapp_bin enclave-Alice)
set(eapp_src eapp/eapp.c)
set(host_bin enclave-Alice-runner)
set(host_src host/host.cpp)
set(package_name "enclave-Alice.ke")
set(package_script "./enclave-Alice-runner enclave-Alice eyrie-rt")

if(RISCV32)
  set(eyrie_plugins "freemem rv32")
else()
  set(eyrie_plugins "freemem")
endif()

# eapp
add_executable(${eapp_bin} ${eapp_src} eapp/eapp_net.h eapp/eapp_net.c eapp/eapp_crt.h eapp/eapp_crt.c eapp/printf.h eapp/printf.c custom_certs.h custom_certs.c riscv_time.h riscv_time.c) 
target_link_libraries(${eapp_bin} "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds" ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE} ${MBEDTLS_LIB_TLS_EAPP} ${MBEDTLS_LIB_X509_EAPP} ${MBEDTLS_LIB_CRYPTO_EAPP})
target_include_directories(${eapp_bin} 
  PUBLIC ${KEYSTONE_SDK_DIR}/include/app
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PRIVATE ${MBEDTLS_DIR_EAPP}/include
  PRIVATE .)

# host
add_executable(${host_bin} ${host_src} host/net.cpp host/net.h host/crt.cpp host/crt.h riscv_time.h riscv_time.c)
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${MBEDTLS_LIB_TLS_HOST_RISCV} ${MBEDTLS_LIB_X509_HOST_RISCV} ${MBEDTLS_LIB_CRYPTO_HOST_RISCV})
target_include_directories(${host_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/host
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PRIVATE ${MBEDTLS_DIR_HOST}/include 
  PRIVATE .)

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

