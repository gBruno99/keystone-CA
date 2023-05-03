set(eapp_bin client)
set(eapp_src eapp/eapp_native.c)
set(host_bin client-runner)
set(host_src host/host_native.cpp)
set(package_name "client.ke")
set(package_script "./client-runner client eyrie-rt")

if(RISCV32)
  set(eyrie_plugins "rv32 freemem")
else()
  set(eyrie_plugins "freemem")
endif()

set(custom_mbedtls_files ../custom_mbedtls/custom_asn1.c ../custom_mbedtls/custom_ed25519.c ../custom_mbedtls/custom_mod.c 
../custom_mbedtls/custom_pk.c ../custom_mbedtls/custom_string.c ../custom_mbedtls/custom_utils.c ../custom_mbedtls/custom_x509.c )
set(custom_mbedtls_dir ../custom_mbedtls/)
set(sha3_dir ../custom_mbedtls/sha3/)
set(ed25519_files ../custom_mbedtls/ed25519/ed25519.h ../custom_mbedtls/ed25519/fe.h ../custom_mbedtls/ed25519/fe.c ../custom_mbedtls/ed25519/fixedint.h
../custom_mbedtls/ed25519/ge.h ../custom_mbedtls/ed25519/ge.c ../custom_mbedtls/ed25519/keypair.c ../custom_mbedtls/ed25519/precomp_data.h
../custom_mbedtls/ed25519/sc.h ../custom_mbedtls/ed25519/sc.c ../custom_mbedtls/ed25519/sign.c ../custom_mbedtls/ed25519/verify.c)

# eapp

add_executable(${eapp_bin} ${eapp_src} ${custom_mbedtls_files} printf.h printf.c 
${sha3_dir}/sha3.h ${sha3_dir}/sha3.c ${ed25519_files})
target_link_libraries(${eapp_bin} "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds" 
${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE}) 
# -nostdlib

target_include_directories(${eapp_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/app
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PRIVATE ${custom_mbedtls_dir}/include
  PRIVATE ${custom_mbedtls_dir}
  PRIVATE .)

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE}
${MBEDTLS_LIB_CRYPTO_HOST} ${MBEDTLS_LIB_TLS_HOST} ${MBEDTLS_LIB_X509_HOST})
# add -std=c++11 flag
set_target_properties(${host_bin}
  PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO
)
target_include_directories(${host_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/host
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PRIVATE ${MBEDTLS_DIR_HOST}/include)

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
