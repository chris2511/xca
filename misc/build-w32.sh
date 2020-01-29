#!/bin/sh -e


XCA_DIR="`dirname $0`"
XCA_DIR="`cd $XCA_DIR/.. && pwd`"

HOST=x86_64-w64-mingw32
export CROSS="${HOST}-"
TARGET=mingw64
read LIBTOOL_DIR < "`dirname $0`/../Libtool.version"
LIBTOOL_GZ="${LIBTOOL_DIR}".tar.gz
LIBTOOL_DL="http://ftp.gnu.org/gnu/libtool/${LIBTOOL_GZ}"

read OPENSSL_DIR < "`dirname $0`/../OpenSSL.version"
OPENSSL_GZ="${OPENSSL_DIR}".tar.gz
OPENSSL_DL="https://www.openssl.org/source/${OPENSSL_GZ}"

unpack() {
  eval "dir=\${$1_DIR} gz=\${$1_GZ} dl=\${$1_DL} PATCH=\${$1_PATCH}"
  test -f "$gz" || curl "$dl" -o "$gz"
  echo "Building '$dir'"
  rm -rf "$dir"
  tar -zxf "$gz"
  cd "$dir"
  if test -f "$PATCH"; then
    patch -p1 < "$PATCH"
    test ! -x bootstrap || ./bootstrap
  fi
}

do_openssl()
{(
unpack OPENSSL
./Configure ${TARGET} shared --cross-compile-prefix="${CROSS}" --prefix="${INSTALL_DIR}"
make && make install_sw
)}

do_libtool()
{(
unpack LIBTOOL
./configure --host ${HOST} --prefix ${INSTALL_DIR}
make && make install
)}


do_XCA()
{(
  mkdir -p $XCA_BUILD
  cd $XCA_BUILD
  $XCA_DIR/configure --host ${HOST} --with-qt=${INSTALL_DIR}/../qt/5.12.0
  make -j5 USE_HOSTTOOLS=no
  cp xca-portable*.zip msi-installer-dir*.zip ..
)}

XCA_BUILD="`pwd`"/xca_build
export INSTALL_DIR=`pwd`/install

if test -f build-libs; then
  do_openssl
  do_libtool
fi
do_XCA
