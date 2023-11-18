# keystone-CA
Thesis implementation: "Design and Implementation of Trusted Channels in the Keystone Framework"

## Commands to generate certificates and keys
- Executed in `mbedtls_builds/mbedtls_host/build_linux/`
- The elliptic curve that is used for keys is **curve secp521r1**

### Commands to generate CA cert:
```
$ ./programs/pkey/gen_key type=ec filename=ca_key.key  
$ ./programs/x509/cert_write selfsign=1 issuer_key=ca_key.key issuer_name=CN=CA,O=CertificateAuthority,C=IT not_before=20230101000000 not_after=20240101000000 is_ca=1 max_pathlen=10 output_file=ca.crt
```

### Commands to generate Ver cert:
```
$ ./programs/pkey/gen_key type=ec filename=ver_key.key 
$ ./programs/x509/cert_write selfsign=1 issuer_key=ver_key.key issuer_name=CN=Ver,O=Verifier,C=IT not_before=20230101000000 not_after=20240101000000 is_ca=0 output_file=ver.crt
```

### Commands to generare Alice cert:
```
$ ./programs/pkey/gen_key type=ec filename=alice_key.key
$ ./programs/x509/cert_write issuer_key=ca_key.key issuer_name=CN=CA,O=CertificateAuthority,C=IT not_before=20230101000000 not_after=20240101000000 is_ca=0 subject_key=alice_key.key subject_name=CN=Alice,O=CertificateAuthority,C=IT output_file=alice.crt
```

### Commands to generare Bob cert:
```
$ ./programs/pkey/gen_key type=ec filename=bob_key.key
$ ./programs/x509/cert_write issuer_key=ca_key.key issuer_name=CN=CA,O=CertificateAuthority,C=IT not_before=20230101000000 not_after=20240101000000 is_ca=0 subject_key=bob_key.key subject_name=CN=Bob,O=CertificateAuthority,C=IT output_file=bob.crt
```
