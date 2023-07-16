set(host_bin server-CA.riscv)
set(host_src host/host.c)

# host
set(my_mbedtls_files ../my_mbedtls_stdlib/custom_asn1.c ../my_mbedtls_stdlib/custom_ed25519.c ../my_mbedtls_stdlib/custom_pk.c ../my_mbedtls_stdlib/custom_md.c ../my_mbedtls_stdlib/custom_utils.c
../my_mbedtls_stdlib/custom_attester.c ../my_mbedtls_stdlib/custom_string.c ../my_mbedtls_stdlib/custom_x509.c ../my_mbedtls_stdlib/custom_x509_crt.c ../my_mbedtls_stdlib/custom_x509_csr.c)
set(my_mbedtls_dir ../my_mbedtls_stdlib/)
set(sha3_dir ../my_mbedtls_stdlib/sha3/)
set(ed25519_files ../my_mbedtls_stdlib/ed25519/ed25519.h ../my_mbedtls_stdlib/ed25519/fe.h ../my_mbedtls_stdlib/ed25519/fe.c ../my_mbedtls_stdlib/ed25519/fixedint.h
../my_mbedtls_stdlib/ed25519/ge.h ../my_mbedtls_stdlib/ed25519/ge.c ../my_mbedtls_stdlib/ed25519/keypair.c ../my_mbedtls_stdlib/ed25519/precomp_data.h
../my_mbedtls_stdlib/ed25519/sc.h ../my_mbedtls_stdlib/ed25519/sc.c ../my_mbedtls_stdlib/ed25519/sign.c ../my_mbedtls_stdlib/ed25519/verify.c)

add_executable(${host_bin} ${host_src} certs.c certs.h ${my_mbedtls_files}
${sha3_dir}/sha3.h ${sha3_dir}/sha3.c ${ed25519_files})
target_link_libraries(${host_bin} ${MBEDTLS_LIB_TLS_HOST} ${MBEDTLS_LIB_X509_HOST} ${MBEDTLS_LIB_CRYPTO_HOST})
target_include_directories(${host_bin} 
  PRIVATE ${MBEDTLS_DIR_HOST}/include
  PRIVATE ${my_mbedtls_dir}/include
  PRIVATE ${my_mbedtls_dir}
  PRIVATE ${sha3_dir}  
  PRIVATE .)


