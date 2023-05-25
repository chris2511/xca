#!/bin/sh -e
set -x

do_openssl()
{
  test -f "$OSSL".tar.gz || curl -O https://www.openssl.org/source/"$OSSL".tar.gz
  test -d "$OSSL" || tar zxf "$OSSL".tar.gz
  mkdir -p ${INSTALL_DIR}/lib
  for arch in x86_64 arm64; do
    mkdir -p "${OSSL}-${arch}"
    (cd ${OSSL}-${arch}
     ../$OSSL/Configure darwin64-${arch}-cc shared \
	--prefix="${INSTALL_DIR}" \
	-mmacosx-version-min="$SDK"
     make -j $JOBS build_libs && make install_sw
    )
    PARTS_crypto="$PARTS_crypto ${OSSL}-${arch}/libcrypto.${OSSL_MAJOR}.dylib"
    PARTS_ssl="$PARTS_ssl ${OSSL}-${arch}/libssl.${OSSL_MAJOR}.dylib"
  done
  rm -f "$INSTALL"/lib/libcrypto.3.dylib "$INSTALL"/lib/libssl.${OSSL_MAJOR}.dylib
  lipo -create -output "$INSTALL_DIR"/lib/libcrypto.${OSSL_MAJOR}.dylib $PARTS_crypto
  lipo -create -output "$INSTALL_DIR"/lib/libssl.${OSSL_MAJOR}.dylib $PARTS_ssl
}

OSSL_MAJOR="1.1"
OSSL="openssl-1.1.1t"
XCA_DIR="$(cd `dirname $0`/.. && pwd)"
TOP_DIR="`dirname $XCA_DIR`"

BUILDDIR="$TOP_DIR/osx-release"

INSTALL_DIR="$TOP_DIR/install"
SDK="11"
JOBS=7

test -x $INSTALL_DIR/lib/libcrypto.dylib || (cd $TOP_DIR && do_openssl )

cmake -B "$BUILDDIR" "$XCA_DIR" \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	-DCMAKE_PREFIX_PATH="$TOP_DIR/6.5.0/macos/lib/cmake;$INSTALL_DIR" \
	-DCMAKE_OSX_DEPLOYMENT_TARGET=$SDK

cmake --build "$BUILDDIR" -j$JOBS

cd "$BUILDDIR" && cpack
