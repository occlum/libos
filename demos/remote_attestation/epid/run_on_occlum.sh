#!/usr/bin/env bash

THISDIR="$(dirname $(readlink -f $0))"
DEMPOAPP="remote_attestation_demo"

# 1. Init Occlum Workspace
rm -rf $THISDIR/occlum_workspace && \
mkdir -p $THISDIR/occlum_workspace && \
cd occlum_workspace &&
occlum init || exit 1

# 2. Copy files into Occlum Workspace and Build
mkdir -p image/etc
mkdir -p image/etc/certs
cp /etc/resolv.conf image/etc
cp /etc/hosts image/etc
cp $THISDIR/conf/ra_config.json image/etc/
cp $THISDIR/build/$DEMPOAPP image/bin
cp /usr/local/occlum/x86_64-linux-musl/lib/libssl.so.1.1 image/lib
cp /usr/local/occlum/x86_64-linux-musl/lib/libcrypto.so.1.1 image/lib
cp /usr/local/occlum/x86_64-linux-musl/lib/libcurl.so.4 image/lib
occlum build

# 3. Run application
LOG_LEVEL=${1:-off}
OCCLUM_LOG_LEVEL=$LEVEL occlum run /bin/$DEMPOAPP
