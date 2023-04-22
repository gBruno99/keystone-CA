#!/bin/bash

set -e

echo -e "This is a quick-start build script for the Keystone CA, it
will clone and build all the necessary parts to run the demo
server/applcation and client on a RISC-V platform (ex: qemu). Please
ensure you have cloned keystone completely and that you have fully
built the sdk tests and run them successfully in qemu.

You must set KEYSTONE_SDK_DIR to the install directory of Keystone SDK.

You must have the riscv64 gcc on-path as well. (e.g. run
'source source.sh' in the Keystone directory.

If you have already started building Mbed TLS / etc, it is not
recommended to use this script."
read -r -p "Continue? [Y/n] " response
response=${response,,}
if [[ "$response" =~ ^(no|n)$ ]]
then
    exit 0
fi

# Check location/tools
if [[ ! -v KEYSTONE_SDK_DIR ]]
then
    echo "KEYSTONE_SDK_DIR not set! Please set this to the location where Keystone SDK has been installed."
    exit 0
fi

if [[ ! $(command -v riscv64-unknown-linux-gnu-gcc) ]]
then
    echo "No riscv64 gcc available. Make sure you've run \"source source.sh\" in the Keystone directory (or equivalent.)";
    exit 0
fi

DEMO_DIR=$(pwd)

set -e

# Clone, checkout, and build the mbedtls library
if [ ! -d mbedtls_build ]
then
  git clone https://github.com/Mbed-TLS/mbedtls.git mbedtls_build
  cd mbedtls_build
  git checkout 3c3b94a31b9d91e1579c48165658486171c82a36
  python3 -m pip install --user -r scripts/basic.requirements.txt
  mkdir build && cd build
  cmake -DCMAKE_TOOLCHAIN_FILE=../../riscv-toolchain.cmake -DENABLE_TESTING=0ff ..
  cmake --build .
  cd ../..
fi

export MBEDTLS_DIR=$(pwd)/mbedtls_build/

# Build the demo
mkdir -p build
cd build
cmake ..
make
make client-package
make hello-package

# copy enclave packages - only for me
cp hello/hello.ke ../../keystone/build/overlay/root/
cp client/client.ke ../../keystone/build/overlay/root/

# Done!
echo -e "************ Demo binaries built and copied into overlay directory. ***************
            Run 'make image' in the Keystone build dir, and the demo binaries should
            be available in qemu next time you start it!"
