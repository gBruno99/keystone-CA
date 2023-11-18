#!/bin/bash

set -e

source source.sh

# Build mbedtls libraries
cd ./scripts/
./build_mbedtls.sh

# Build applications
cd ../build/
cmake ..
make
make enclave-Alice-package
make enclave-Bob-package

cp enclave-Alice/enclave-Alice.ke ../../keystone/build/overlay/root/
cp enclave-Bob/enclave-Bob.ke ../../keystone/build/overlay/root/

# Update keystone image
cd ../../keystone/build/
make image

# Update reference values
cd ../../keystone-CA/scripts/
./update_reference_values.sh

# Re-build the applications
cd ../build/
cmake ..
make
make enclave-Alice-package
make enclave-Bob-package

cp enclave-Alice/enclave-Alice.ke ../../keystone/build/overlay/root/
cp enclave-Bob/enclave-Bob.ke ../../keystone/build/overlay/root/

# Re-update keystone image
cd ../../keystone/build/
make image
