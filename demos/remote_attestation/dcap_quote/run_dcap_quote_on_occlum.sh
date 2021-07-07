#!/bin/bash
occlum_glibc=/opt/occlum/glibc/lib/

set -e

BLUE='\033[1;34m'
NC='\033[0m'
INSTANCE_DIR="occlum_instance"

pushd dcap_lib
cargo build --all-targets
popd

make -C c_app

rm -rf ${INSTANCE_DIR} && occlum new ${INSTANCE_DIR}
cd ${INSTANCE_DIR}
cp ../dcap_lib/target/debug/examples/dcap_test image/bin
cp ../dcap_lib/target/debug/libdcap_quote.so image/$occlum_glibc
cp ../c_app/dcap_c_test image/bin
cp $occlum_glibc/libdl.so.2 image/$occlum_glibc
cp $occlum_glibc/librt.so.1 image/$occlum_glibc

occlum build

echo -e "${BLUE}occlum run rust test /bin/dcap_test${NC}"
occlum run /bin/dcap_test

echo -e "************"

echo -e "${BLUE}occlum run C test /bin/dcap_c_test${NC}"
occlum run /bin/dcap_c_test
