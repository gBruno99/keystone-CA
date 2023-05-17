set(eapp_bin hello-native)
set(eapp_src eapp/eapp_native.c)
set(host_bin hello-native-runner)
set(host_src host/host_native.cpp)
set(package_name "hello-native.ke")
set(package_script "./hello-native-runner hello-native eyrie-rt")

if(RISCV32)
  set(eyrie_plugins "rv32 freemem")
else()
  set(eyrie_plugins "freemem")
endif()

set(my_mbedtls_files ../my_mbedtls/my_asn1.c ../my_mbedtls/my_ed25519.c ../my_mbedtls/my_pk.c ../my_mbedtls/my_utils.c
 ../my_mbedtls/custom_string.c ../my_mbedtls/my_x509.c ../my_mbedtls/my_x509_crt.c)
set(my_mbedtls_dir ../my_mbedtls/)
set(sha3_dir ../my_mbedtls/sha3/)
set(ed25519_files ../my_mbedtls/ed25519/ed25519.h ../my_mbedtls/ed25519/fe.h ../my_mbedtls/ed25519/fe.c ../my_mbedtls/ed25519/fixedint.h
../my_mbedtls/ed25519/ge.h ../my_mbedtls/ed25519/ge.c ../my_mbedtls/ed25519/keypair.c ../my_mbedtls/ed25519/precomp_data.h
../my_mbedtls/ed25519/sc.h ../my_mbedtls/ed25519/sc.c ../my_mbedtls/ed25519/sign.c ../my_mbedtls/ed25519/verify.c)

# eapp

add_executable(${eapp_bin} ${eapp_src} ${my_mbedtls_files} printf.h printf.c 
${sha3_dir}/sha3.h ${sha3_dir}/sha3.c ${ed25519_files})
target_link_libraries(${eapp_bin} "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds" ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE})

target_include_directories(${eapp_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/app
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PRIVATE ${my_mbedtls_dir}/include
  PRIVATE ${my_mbedtls_dir}
  PRIVATE ${sha3_dir}
  PRIVATE .)

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})
# add -std=c++11 flag
set_target_properties(${host_bin}
  PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO
)
target_include_directories(${host_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/host
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge)

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

