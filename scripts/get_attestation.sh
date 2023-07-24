#!/bin/bash

# Usage (from ./scripts): KEYSTONE_BUILD_DIR=../../keystone/build ./get_attestation.sh ../my_mbedtls_stdlib/include/

output_path=$1

if [ "${output_path}xxx" = "xxx" ]; then
    echo You must set the directory which will hold the build files to copy over!;
    exit
fi

if [ -z "$KEYSTONE_BUILD_DIR" -a "${KEYSTONE_BUILD_DIR+xxx}" = "xxx" ]; then
    echo You MUST set KEYSTONE_BUILD_DIR.;
    exit
fi

genhash () {
    echo "Generating hash ($2) for \"$1\""
    echo $2 | xxd -r -p - > $1_reference_value
    xxd -i $1_reference_value > $1_reference_value.h
    rm $1_reference_value
}

extracthash () {
    # Generalize me!
    expect_commands='
    set timeout 60
    cd $::env(KEYSTONE_BUILD_DIR)
    spawn ./scripts/run-qemu.sh
    expect "*?ogin" { send "root\r" }
    expect "*?assword" { send "sifive\r" }

    expect "# " { send "insmod keystone-driver.ko\r" }


    expect "# " { send "ifdown lo && ifup lo\r" }
    expect "# " { send "./server-CA.riscv &\r" }
    expect "# " { send "./enclave-Alice.ke\r" }


    expect "# " { send "poweroff\r" }
    expect eof
    '
    expect -c "${expect_commands//
/;}"
}


extracthash | tee extract_hash.log
SM_HASH=$(awk '/TCI sm:/' extract_hash.log  | cut -c 11-)
EAPP_HASH=$(awk '/TCI enclave:/' extract_hash.log  | cut -c 16-)
rm -f extract_hash.log
cd $output_path
if [ "${SM_HASH}xxx" = "xxx" ]; then
    echo Could not extract the SM_HASH!;
    exit
fi
if [ "${EAPP_HASH}xxx" = "xxx" ]; then
    echo Could not extract the EAPP_HASH!;
    exit
fi
genhash sm $SM_HASH
genhash enclave $EAPP_HASH
