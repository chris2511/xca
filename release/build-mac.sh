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
  ZBUILD=zstd-$ZSTDV
  tar -zxf ${ARCHIVE}
  (cd "$ZBUILD"
    export CFLAGS="-arch x86_64 -arch arm64 -mmacosx-version-min=$SDK"
    export PREFIX="$INSTALL_DIR"
    make -j$JOBS && make install
    unset CFLAGS PREFIX
  )
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

do_postgres()
{
  PGV=17.4
  ARCHIVE=postgresql-$PGV.tar.gz
  test -f $ARCHIVE || curl -L https://ftp.postgresql.org/pub/source/v$PGV/$ARCHIVE -O
  tar -zxf ${ARCHIVE}
  (cd postgresql-$PGV
    CFLAGS="-arch x86_64 -arch arm64 -mmacosx-version-min=$SDK" \
    ./configure --with-ssl=openssl --without-icu --prefix="${INSTALL_DIR}" \
       --with-includes="$INSTALL_DIR"/include --with-libraries="$INSTALL_DIR"/lib
    make -j$JOBS && make install
  )
}

# need to install ninja via "brew install ninja"
do_qsql()
{
  PLUGIN="$QT_DIR/plugins/sqldrivers/libqsqlmysql.dylib"
#  test -f "$PLUGIN" && return
  SQL_BUILD="$TOP_DIR/build-sqlplugins"
  ( cd "$QT_DIR/../Src/qtbase"
    ./configure -cmake-generator Ninja -release -no-feature-x86intrin -sql-mysql -sql-psql \
	CMAKE_BUILD_TYPE=Release \
	CMAKE_PREFIX_PATH="$INSTALL_DIR" \
	CMAKE_OSX_DEPLOYMENT_TARGET=$SDK \
  )

  rm -rf "$SQL_BUILD"
  mkdir -p "$SQL_BUILD"

  cmake -B $SQL_BUILD -G "Ninja" \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	-DCMAKE_INSTALL_PREFIX="$QT_DIR" \
	-DCMAKE_OSX_DEPLOYMENT_TARGET=$SDK \
	-DMySQL_ROOT="$INSTALL_DIR" \
	-DPostgreSQL_ROOT="$INSTALL_DIR" \
	-DFEATURE_sql_odbc=OFF -DFEATURE_sql_sqlite=OFF \
	"$QT_SQL_SRC"

  cmake --build $SQL_BUILD -j$JOBS
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
OSSL="openssl-3.4.1"
XCA_DIR="$(cd `dirname $0`/.. && pwd)"
TOP_DIR="`dirname $XCA_DIR`"
QT_DIR="$TOP_DIR/6.8.3/macos"
QT_SQL_SRC="$QT_DIR/../Src/qtbase/src/plugins/sqldrivers"

BUILDDIR="$TOP_DIR/osx-release-dmg"
BUILDDIR_APPSTORE="$TOP_DIR/osx-release-appstore"

INSTALL_DIR="$TOP_DIR/install"
SDK="11.0"
JOBS=7

cd $TOP_DIR
do_openssl
#do_zstd
#do_mariadb_connector_c
#do_postgres
# aqt install-src mac 6.8.3 --archives qtbase
if grep qt_internal_force_macos_intel_arch $QT_SQL_SRC/mysql/CMakeLists.txt; then
  (cd $QT_SQL_SRC && patch -p5 < $XCA_DIR/misc/qsqlmysql.patch)
fi

do_qsql

cmake -B "$BUILDDIR" "$XCA_DIR" \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	-DCMAKE_PREFIX_PATH="$QT_DIR/lib/cmake;$INSTALL_DIR" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_OSX_DEPLOYMENT_TARGET=$SDK

cmake --build "$BUILDDIR" -j$JOBS

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

if find "${BUILDDIR_APPSTORE}/xca.app" "${BUILDDIR}/xca.app" -name "*.dylib" | xargs otool -L | grep -e "/Applications/\|\t$HOME"
then
  echo
  echo "Error: some libraries are linked to /Applications or $HOME"
  exit 1
fi
