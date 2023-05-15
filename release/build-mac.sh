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
    PARTS_crypto="$PARTS_crypto ${OSSL}-${arch}/libcrypto.3.dylib"
    PARTS_ssl="$PARTS_ssl ${OSSL}-${arch}/libssl.3.dylib"
  done
  rm -f "$INSTALL"/lib/libcrypto.3.dylib "$INSTALL"/lib/libssl.3.dylib
  lipo -create -output "$INSTALL_DIR"/lib/libcrypto.3.dylib $PARTS_crypto
  lipo -create -output "$INSTALL_DIR"/lib/libssl.3.dylib $PARTS_ssl
}

OSSL="openssl-3.0.8"
XCA_DIR="$(cd `dirname $0`/.. && pwd)"
TOP_DIR="`dirname $XCA_DIR`"

BUILDDIR="$TOP_DIR/osx-release"

INSTALL_DIR="$TOP_DIR/install"
SDK="10.14"
JOBS=7

test -x $INSTALL_DIR/lib/libcrypto.dylib || (cd $TOP_DIR && do_openssl )

cmake -B "$BUILDDIR" "$XCA_DIR" \
	-DOPENSSL_ROOT_DIR="$INSTALL_DIR" \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	-DCMAKE_PREFIX_PATH="$TOP_DIR/6.5.0/macos/lib/cmake"

cmake --build "$BUILDDIR" -j$JOBS

cd "$BUILDDIR" && cpack
