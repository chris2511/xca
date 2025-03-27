#!/bin/sh

# in C:\msys64\msys2.ini: MSYS2_PATH_TYPE=inherit
# pacman -S vim make zip

# Build xca on Windows 
do_openssl() {
  test -f $INSTALL_DIR/bin/libcrypto-3-x64.dll && return
  test -f "$OSSL".tar.gz || curl -L -O https://www.openssl.org/source/"$OSSL".tar.gz
  test -d "$OSSL" || tar zxf "$OSSL".tar.gz
  cd "$OSSL"
  ./Configure mingw64 --prefix=$INSTALL_DIR --libdir=lib no-module
  make -j4
  make install
}

OSSL="openssl-3.4.1"
XCA_DIR="$(cd `dirname $0`/.. && pwd)"
TOP_DIR="`dirname $XCA_DIR`"
BUILDDIR="$TOP_DIR/w64-release"
INSTALL_DIR="$TOP_DIR/OpenSSL"
JOBS=7

cd $TOP_DIR
do_openssl

cd $TOP_DIR
cmake -B "$BUILDDIR" -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="$INSTALL_DIR" $XCA_DIR
cmake --build "$BUILDDIR" -j$JOBS
cmake --build "$BUILDDIR" -t install
cd "$BUILDDIR" && cpack
