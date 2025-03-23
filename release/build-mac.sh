#!/bin/sh -e
set -x

do_openssl()
{
  test -x $INSTALL_DIR/lib/libcrypto.dylib && return

  test -f "$OSSL".tar.gz || curl -L -O https://github.com/openssl/openssl/releases/download/$OSSL/${OSSL}.tar.gz
  test -d "$OSSL" || tar zxf "$OSSL".tar.gz
  mkdir -p ${INSTALL_DIR}/lib
  for arch in x86_64 arm64; do
    mkdir -p "${OSSL}-${arch}"
    (cd ${OSSL}-${arch}
     ../$OSSL/Configure darwin64-${arch}-cc shared no-module \
	--prefix="${INSTALL_DIR}" \
	-mmacosx-version-min="$SDK"
     make -j $JOBS build_libs && make install_sw
    )
    PARTS_crypto="$PARTS_crypto ${OSSL}-${arch}/libcrypto.${OSSL_MAJOR}.dylib"
    PARTS_ssl="$PARTS_ssl ${OSSL}-${arch}/libssl.${OSSL_MAJOR}.dylib"
  done
  rm -f "$INSTALL"/lib/libcrypto.${OSSL_MAJOR}.dylib \
	"$INSTALL"/lib/libssl.${OSSL_MAJOR}.dylib
  lipo -create -output "$INSTALL_DIR"/lib/libcrypto.${OSSL_MAJOR}.dylib $PARTS_crypto
  lipo -create -output "$INSTALL_DIR"/lib/libssl.${OSSL_MAJOR}.dylib $PARTS_ssl
}

do_zstd()
{
  ZSTDV=1.5.6
  ARCHIVE=zstd-${ZSTDV}.tar.gz
  test -f $ARCHIVE || curl -L https://github.com/facebook/zstd/archive/refs/tags/v${ZSTDV}.tar.gz -o ${ARCHIVE}
  for arch in x86_64 arm64; do
    ZBUILD=zstd-${arch}
    mkdir -p "$ZBUILD"
    (cd "$ZBUILD"
      tar -zxf ../${ARCHIVE} --strip-components 1
      export CFLAGS="-target ${arch}-apple-macos11 -mmacosx-version-min=$SDK"
      export PREFIX="$INSTALL_DIR"
      make -j5 && make install
    )
    # DESTDIR="$INSTALL_DIR" make install
    PARTS_dylib="$PARTS_dylib $ZBUILD/lib/libzstd.dylib"
    PARTS_a="$PARTS_a $ZBUILD/lib/libzstd.a"
  done
  rm -f "$INSTALL_DIR"/lib/libzstd.dylib "$INSTALL_DIR"/lib/libzstd.a
  lipo -create -output "$INSTALL_DIR"/lib/libzstd.dylib $PARTS_dylib
  lipo -create -output "$INSTALL_DIR"/lib/libzstd.a $PARTS_a
}

do_mariadb_connector_c()
{
  REPO=mariadb-connector-c-3.4.1-src
  ARCHIVE=${REPO}.tar.gz
  test -f $ARCHIVE || curl -LO https://mirror.kumi.systems/mariadb/connector-c-3.4.1/$ARCHIVE
  test -d $REPO || tar zxf "$ARCHIVE"
  B="$TOP_DIR/mariadb-build"
  mkdir -p ${B}
  cmake -B ${B} -DCMAKE_C_FLAGS=-Wno-deprecated-non-prototype \
	-DCMAKE_BUILD_TYPE=RelWithDebInfo \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	-DCMAKE_PREFIX_PATH="$INSTALL_DIR" \
	-DINSTALL_LIBDIR=lib -DCMAKE_MACOSX_RPATH=1 \
	-DWITH_EXTERNAL_ZLIB=OFF \
	-DCMAKE_OSX_DEPLOYMENT_TARGET=$SDK \
	-S $TOP_DIR/$REPO
  cmake --build ${B} -j$JOBS
  cmake --install ${B} --prefix="$INSTALL_DIR"
}

# need to install ninja via "brew install ninja"
do_qsqlmysql()
{
  PLUGIN="$QT_DIR/plugins/sqldrivers/libqsqlmysql.dylib"
#  test -f "$PLUGIN" && return
  SQL_BUILD="$TOP_DIR/build-sqlplugins"
  ( cd "$QT_DIR/../Src/qtbase"
    ./configure -cmake-generator Ninja -release -no-feature-x86intrin -sql-mysql \
	CMAKE_BUILD_TYPE=Release \
	CMAKE_PREFIX_PATH="$INSTALL_DIR" \
	CMAKE_OSX_DEPLOYMENT_TARGET=$SDK \
	DMySQL_ROOT="$INSTALL_DIR" \
	FEATURE_sql_odbc=OFF FEATURE_sql_sqlite=OFF
  )

  rm -rf "$SQL_BUILD"
  mkdir -p "$SQL_BUILD"

  cmake -B $SQL_BUILD -G "Ninja" \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	-DCMAKE_INSTALL_PREFIX="$QT_DIR" \
	-DCMAKE_OSX_DEPLOYMENT_TARGET=$SDK \
	-DMySQL_ROOT="$INSTALL_DIR" \
	"$QT_DIR/../Src/qtbase/src/plugins/sqldrivers"

  cmake --build $SQL_BUILD -j$JOBS -v
  cmake --install $SQL_BUILD
  # Replace @rpath name by full path in the installed file,
  # to trigger macdeployqt to pick up this library.
  # This is a hack, but it works. we need to revert it
  # after macdeployqt has run.
  install_name_tool -change @rpath/libmariadb.3.dylib \
                "$INSTALL_DIR"/lib/libmariadb.3.dylib \
        $QT_DIR/plugins/sqldrivers/libqsqlmysql.dylib

  file $QT_DIR/plugins/sqldrivers/libqsqlmysql.dylib
  otool -L $QT_DIR/plugins/sqldrivers/libqsqlmysql.dylib
}

OSSL_MAJOR="3"
OSSL="openssl-3.3.2"
XCA_DIR="$(cd `dirname $0`/.. && pwd)"
TOP_DIR="`dirname $XCA_DIR`"
QT_DIR="$TOP_DIR/6.6.3/macos"

BUILDDIR="$TOP_DIR/osx-release-dmg"
BUILDDIR_APPSTORE="$TOP_DIR/osx-release-appstore"

INSTALL_DIR="$TOP_DIR/install"
SDK="11.0"
JOBS=7

cd $TOP_DIR
do_openssl
#do_zstd
#do_mariadb_connector_c
# aqt install-src mac 6.6.3 --archives qtbase
# patch -p1 < $XCA_DIR/misc/qsqlmysql.patch
do_qsqlmysql

cmake -B "$BUILDDIR" "$XCA_DIR" \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	-DCMAKE_PREFIX_PATH="$QT_DIR/lib/cmake;$INSTALL_DIR" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_OSX_DEPLOYMENT_TARGET=$SDK

cmake --build "$BUILDDIR" -j$JOBS

if test -d /Applications/Postgres.app; then
	echo "###### Hey Christian, rename /Applications/Postgres.app when linking, to skip those drivers !!"
	# If the Postgres.app exists, macdeployqt will take that libpg.dylib and
	# install it inside XCA. This destroys other links to libssl-1.1 ...
	# Let the users install /Applications/Postgres.app
fi
(cd "$BUILDDIR" && cpack)

######## Create the AppStore Package
cmake -B "$BUILDDIR_APPSTORE" "$XCA_DIR" \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	-DCMAKE_PREFIX_PATH="$QT_DIR/lib/cmake;$INSTALL_DIR" \
	-DCMAKE_OSX_DEPLOYMENT_TARGET=$SDK \
	-DAPPSTORE_COMPLIANT=ON \
	-DCMAKE_BUILD_TYPE=Release \
	-DPROVISIONPROFILE="$TOP_DIR/XCA_AppStore_Provisioning.provisionprofile"

read xca_version < "$BUILDDIR_APPSTORE"/PKGVERSION.txt
cmake --build "$BUILDDIR_APPSTORE" -j$JOBS
productbuild --component "$BUILDDIR_APPSTORE/xca.app" /Applications \
    --sign "3rd Party Mac Developer Installer" "$BUILDDIR_APPSTORE/xca-${xca_version}-appstore.pkg"

find "${BUILDDIR_APPSTORE}/xca.app" "${BUILDDIR}/xca.app" -name "*.dylib" | xargs otool -L | grep -E "/Applications/\|$HOME"
