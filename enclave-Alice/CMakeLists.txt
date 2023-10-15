set(eapp_bin enclave-Alice)
set(eapp_src eapp/hello_new.c)
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

# set(my_mbedtls_files ../my_mbedtls/custom_asn1.c ../my_mbedtls/custom_ed25519.c ../my_mbedtls/custom_pk.c ../my_mbedtls/custom_md.c ../my_mbedtls/custom_utils.c
# ../my_mbedtls/custom_attester.c ../my_mbedtls/custom_string.c ../my_mbedtls/custom_x509.c ../my_mbedtls/custom_x509_crt.c ../my_mbedtls/custom_x509_csr.c)
# set(my_mbedtls_dir ../my_mbedtls/)
# set(sha3_dir ../my_mbedtls/sha3/)
# set(ed25519_files ../my_mbedtls/ed25519/ed25519.h ../my_mbedtls/ed25519/fe.h ../my_mbedtls/ed25519/fe.c ../my_mbedtls/ed25519/fixedint.h
# ../my_mbedtls/ed25519/ge.h ../my_mbedtls/ed25519/ge.c ../my_mbedtls/ed25519/keypair.c ../my_mbedtls/ed25519/precomp_data.h
# ../my_mbedtls/ed25519/sc.h ../my_mbedtls/ed25519/sc.c ../my_mbedtls/ed25519/sign.c ../my_mbedtls/ed25519/verify.c)

add_executable(${eapp_bin} ${eapp_src} certs.c certs.h eapp/eapp_net.h eapp/eapp_net.c eapp/eapp_crt.h eapp/eapp_crt.c eapp/printf.h eapp/printf.c) 
# ${my_mbedtls_files} ${sha3_dir}/sha3.h ${sha3_dir}/sha3.c ${ed25519_files})
target_link_libraries(${eapp_bin} "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds" ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE} ${MBEDTLS_LIB_TLS_EAPP} ${MBEDTLS_LIB_X509_EAPP} ${MBEDTLS_LIB_CRYPTO_EAPP})
target_include_directories(${eapp_bin} 
  PUBLIC ${KEYSTONE_SDK_DIR}/include/app
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PRIVATE ${MBEDTLS_DIR_EAPP}/include
# PRIVATE ${my_mbedtls_dir}/include
# PRIVATE ${my_mbedtls_dir}
# PRIVATE ${sha3_dir} 
  PRIVATE .)

# host

add_executable(${host_bin} ${host_src} host/net.cpp host/net.h host/crt.cpp host/crt.h)
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${MBEDTLS_LIB_TLS_HOST} ${MBEDTLS_LIB_X509_HOST} ${MBEDTLS_LIB_CRYPTO_HOST})
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

