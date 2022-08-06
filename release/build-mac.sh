#!/bin/sh -e
set -x

do_openssl_arch()
{
  arch="$1"
  openssl="openssl-1.1.1q"
  test -f "$openssl".tar.gz || curl -O https://www.openssl.org/source/"$openssl".tar.gz
  if ! test -d "${openssl}-${arch}"; then
    tar zxf "$openssl".tar.gz
    mv "$openssl" "${openssl}-${arch}"
  fi
  (cd ${openssl}-${arch}
   ./Configure darwin64-${arch}-cc shared \
	--prefix="${INSTALL_DIR}-${arch}" \
	-mmacosx-version-min="$SDK"
   make -j $JOBS build_libs && make install_dev
  )
}

do_openssl()
{
  mkdir -p ${INSTALL_DIR}/lib
  do_openssl_arch x86_64
  do_openssl_arch arm64

  lipo -create ${INSTALL_DIR}-*/lib/libcrypto.*.dylib -output ${INSTALL_DIR}/lib/libcrypto.1.1.dylib
  lipo -create ${INSTALL_DIR}-*/lib/libssl.*.dylib -output ${INSTALL_DIR}/lib/libssl.1.1.dylib
  cp -a ${INSTALL_DIR}-arm64/include ${INSTALL_DIR}
  ln -s libcrypto.1.1.dylib ${INSTALL_DIR}/lib/libcrypto.dylib
  ln -s libssl.1.1.dylib ${INSTALL_DIR}/lib/libssl.dylib

#  chmod 755 $INSTALL_DIR/lib/*.dylib
}

XCA_DIR="$(cd `dirname $0`/.. && pwd)"
TOP_DIR="`dirname $XCA_DIR`"

BUILDDIR="$TOP_DIR/osx-release"

INSTALL_DIR="$TOP_DIR/install"
SDK="10.13"
JOBS=4
ARCHIVE="xcarch.xcarchive"
test -x $INSTALL_DIR/lib/libcrypto.dylib || (cd $TOP_DIR && do_openssl )

cmake -B "$BUILDDIR" "$XCA_DIR" \
	-DOPENSSL_ROOT_DIR="$INSTALL_DIR" \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64"
cmake --build "$BUILDDIR" -j4

echo xcodebuild -scheme package \
	   -jobs $JOBS \
	   -configuration Release\
	   -parallelizeTargets \
	   -archivePath $ARCHIVE \
	   CODE_SIGN_IDENTITY="${APPLE_DEVELOPER_HASH}" \
	   build archive

echo xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportOptionsPlist "$XCA_DIR/misc/ExportOptions.plist" -exportPath Release

#/usr/bin/ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"
