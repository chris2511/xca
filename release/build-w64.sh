#!/bin/sh

# in C:\msys64\msys2.ini: MSYS2_PATH_TYPE=inherit

# Build xca on Windows 
do_openssl() {
  test -f $INSTALL_DIR/bin/libcrypto-3-x64.dll && return
  test -f "$OSSL".tar.gz || curl -O https://www.openssl.org/source/"$OSSL".tar.gz
  test -d "$OSSL" || tar zxf "$OSSL".tar.gz
  cd "$OSSL"
  ./Configure mingw64 --prefix=/c/OpenSSL --libdir=lib
  make -j4
  make install
}

BUILD=build
OSSL="openssl-3.1.3"
XCA_DIR="$(cd `dirname $0`/.. && pwd)"
TOP_DIR="`dirname $XCA_DIR`"
QT_DIR="$TOP_DIR/6.5.3/mingw_64"

BUILDDIR="$TOP_DIR/w64-release"

INSTALL_DIR="/c/OpenSSL"
JOBS=7

cd $TOP_DIR

do_openssl

cmake -B "$BUILDDIR" -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="$QT_DIR" xca
cmake --build "$BUILDDIR" -j5
cmake --build "$BUILDDIR" -t install
cd "$BUILDDIR" && cpack
