#!/bin/sh

# in C:\msys64\msys2.ini: MSYS2_PATH_TYPE=inherit

# Build xca on Windows 
do_openssl() {
  test -f $INSTALL_DIR/bin/libcrypto-3-x64.dll && return
  test -f "$OSSL".tar.gz || curl -O https://www.openssl.org/source/"$OSSL".tar.gz
  test -d "$OSSL" || tar zxf "$OSSL".tar.gz
  cd "$OSSL"
  ./Configure mingw64 --prefix=$INSTALL_DIR --libdir=lib
  make -j4
  make install
}

OSSL="openssl-3.1.5"
XCA_DIR="$(cd `dirname $0`/.. && pwd)"
TOP_DIR="`dirname $XCA_DIR`"
QT_DIR="$TOP_DIR/QT/6.6.2/mingw_64"
BUILDDIR="$TOP_DIR/w64-release"
INSTALL_DIR="/c/OpenSSL"
JOBS=7

PATH="$TOP_DIR/QT/Tools/mingw1120_64/bin:$INSTALL_DIR/bin:$PATH"

cd $TOP_DIR
do_openssl

cd $TOP_DIR
cmake -B "$BUILDDIR" -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="$QT_DIR:$INSTALL_DIR" xca
cmake --build "$BUILDDIR" -j5
cmake --build "$BUILDDIR" -t install
cd "$BUILDDIR" && cpack
