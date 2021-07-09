#!/usr/bin/env bash

THISDIR="$(dirname $(readlink -f $0))"
INSTALLDIR="/usr/local/occlum/x86_64-linux-musl"
OCCLUMCC="/usr/local/occlum/bin/occlum-gcc"
OCCLUMCXX="/usr/local/occlum/bin/occlum-g++"

export CC=$OCCLUMCC
export CXX=$OCCLUMCXX
export PATH=$PATH:$INSTALLDIR/bin
export PKG_CONFIG_LIBDIR=$PKG_CONFIG_LIBDIR:$INSTALLDIR/lib

DEPSDIR="$THISDIR/deps"

ALL_COMPONENTS="openssl libcurl demo"
OPENSSLDIR=openssl
CURLDIR=curl
CPPCODECDIR=cppcodec
RAPIDJSONDIR=rapidjson

SHOW_HELP() {
    LOG_INFO "Usage: $0 [component-name]\n"
    LOG_INFO "Build component in [$ALL_COMPONENTS] or all by default\n"
    exit 0
}

LOG_DEBUG() {
    echo -e "\033[36m$@\033[0m"
}

LOG_INFO() {
    echo -e "\033[32m$@\033[0m"
}

LOG_ERROR() {
    echo -e "\033[31m$@\033[0m"
}

ERROR_EXIT() {
  LOG_ERROR "$@" && exit 1
}

TRYGET() {
    local dst=$1
    local url=$2
    local pkg=${3:-$(basename $url)}
    local flag="./occlum_demo_source"

    # Download package tarball
    if [ ! -e $pkg ] ; then
        LOG_DEBUG "Downloading $pkg ..."
        wget $url -O $pkg || ERROR_EXIT "Fail to download $pkg"
    else
        LOG_INFO "[READY] $pkg"
    fi

    # Prepare the source code directory
    if [ ! -f $dst/$flag ] ; then
        LOG_DEBUG "Preparing source code: $dst ..."
        mkdir -p $dst && \
        tar -xvf $pkg -C $dst --strip-components 1 >/dev/null || \
        ERROR_EXIT "Fail to extract archive file $pkg"
        touch $dst/$flag && \
        LOG_DEBUG "Prepare $(basename $dst) source code successfully"
    else
        LOG_INFO "[READY] $dst"
    fi
}

openssl_check() {
    [ -f "$INSTALLDIR/lib/libcrypto.so" ] || return 1
}

openssl_build() {
    cd "$DEPSDIR/$OPENSSLDIR" && \
    CC=$OCCLUMCC CXX=$OCCLUMCXX \
    ./config --prefix=$INSTALLDIR \
      --openssldir=/usr/local/occlum/ssl \
      --with-rand-seed=rdcpu \
      no-zlib no-async no-tests && \
    make -j && make install
}

libcurl_check() {
    [ -f "$INSTALLDIR/lib/libcurl.so" ] || return 1
}

libcurl_build() {
    cd "$DEPSDIR/$CURLDIR"
    if [ ! -f ./configure ] ; then
      LOG_DEBUG "Building configure file ..."
      ./buildconf || exit 1
    fi
    CC=$OCCLUMCC CXX=$OCCLUMCXX \
    ./configure \
      --prefix=$INSTALLDIR \
      --with-ssl=$INSTALLDIR \
      --without-zlib && \
    make -j && make install
}

demo_check() {
  return 1  # return false to always build it
}

demo_build() {
    cd "$THISDIR"
    rm -rf build && mkdir build && cd build && \
    cmake ../ \
      -DCMAKE_NO_SYSTEM_FROM_IMPORTED=TRUE \
      -DCMAKE_CXX_COMPILER=$OCCLUMCXX \
      -DBUILD_MODE=${BUILDMODE} && \
    make -j $BUILDVERBOSE && \
    cp $THISDIR/build/libocclumra.a $INSTALLDIR/lib
}

# Show help menu
[ "$1" == "-h" -o "$1" == "--help" ] && SHOW_HELP

# Check the build mode
BUILDMODE="Release"
BUILDVERBOSE=""
if [ "$1" == "--debug" ] ; then
  BUILDMODE="Debug"
  BUILDVERBOSE="VERBOSE=1"
  shift;
fi

# Build specified component or all by default
BUILD_COMPONENTS="${1:-$ALL_COMPONENTS}"

# Download all components once here together
mkdir -p $DEPSDIR && cd $DEPSDIR || exit 1
TRYGET $OPENSSLDIR https://github.com/openssl/openssl/archive/OpenSSL_1_1_1.tar.gz
TRYGET $CURLDIR https://github.com/curl/curl/archive/curl-7_70_0.tar.gz
TRYGET $CPPCODECDIR https://github.com/tplgy/cppcodec/archive/v0.2.tar.gz cppcodec-0.2.tar.gz
TRYGET $RAPIDJSONDIR https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz rapidjson-1.1.0.tar.gz

for i in $BUILD_COMPONENTS ; do
    ${i}_check && LOG_INFO "[READY] build check for $i" && continue
    LOG_DEBUG "Building $i ..." && ${i}_build && \
    LOG_DEBUG "Build $i successfully" || ERROR_EXIT "Fail to build $i"
done

