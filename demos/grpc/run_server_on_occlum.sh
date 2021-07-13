#!/bin/bash
INSTALL_DIR=/usr/local/occlum/x86_64-linux-musl
export PATH=$PATH:$INSTALL_DIR/bin

cd server

make -j$(nproc)
if [ $? -ne 0 ]
then
  echo "demo make failed"
  exit 1
fi

rm -rf occlum_instance
mkdir occlum_instance
cd occlum_instance

occlum init
if [ $? -ne 0 ]
then
  echo "occlum init failed"
  exit 1
fi

mkdir -p image/etc
cp ../greeter_server image/bin
cp $INSTALL_DIR/lib/libprotobuf.so.3.10.0.0 image/lib
cp $INSTALL_DIR/lib/libcares.so.2 image/lib
cp $INSTALL_DIR/lib/libz.so.1 image/lib
if [ $? -ne 0 ]
then
  echo "libraries copied failed"
  exit 1
fi

occlum build
if [ $? -ne 0 ]
then
  echo "occlum build failed"
  exit 1
fi

occlum run /bin/greeter_server
