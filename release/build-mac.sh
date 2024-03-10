#!/bin/sh -e
set -x

do_openssl()
{
  test -x $INSTALL_DIR/lib/libcrypto.dylib && return

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

# need to install ninja via "brew install ninja"
do_mysql()
{
  PLUGIN="$QT_DIR/plugins/sqldrivers/libqsqlmysql.dylib"
  #test -f "$PLUGIN" && return

  B="$TOP_DIR/mariadb-build"
  mkdir -p ${B}
  cmake -B ${B} -DCMAKE_C_FLAGS=-Wno-deprecated-non-prototype \
	   -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	   -DCMAKE_PREFIX_PATH="$INSTALL_DIR" \
	   -DINSTALL_LIBDIR=lib \
	   $TOP_DIR/mariadb-connector-c-3.3.7-src
  cmake --build ${B} -j$JOBS
  cmake --install ${B} --prefix="$INSTALL_DIR"

#############################

  SQL_BUILD="$TOP_DIR/build-sqlplugins"
  mkdir -p "$SQL_BUILD"

  cmake -B $SQL_BUILD \
	-DCMAKE_INSTALL_PREFIX="$QT_DIR" \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	-DMySQL_INCLUDE_DIR="$INSTALL_DIR/include/mariadb" \
	-DMySQL_LIBRARY="$INSTALL_DIR/lib/libmariadb.dylib" \
	-DFEATURE_sql_odbc=OFF -DFEATURE_sql_sqlite=OFF \
	"$QT_DIR/../Src/qtbase/src/plugins/sqldrivers"

  cmake --build $SQL_BUILD -j$JOBS
  cmake --install $SQL_BUILD
  install_name_tool -change libmariadb.3.dylib "$INSTALL_DIR"/lib/libmariadb.3.dylib \
                              $QT_DIR/plugins/sqldrivers/libqsqlmysql.dylib
  file  $QT_DIR/plugins/sqldrivers/libqsqlmysql.dylib
  file  $SQL_BUILD/plugins/sqldrivers/libqsqlmysql.dylib
}

OSSL_MAJOR="3"
OSSL="openssl-3.1.5"
XCA_DIR="$(cd `dirname $0`/.. && pwd)"
TOP_DIR="`dirname $XCA_DIR`"
QT_DIR="$TOP_DIR/6.6.2/macos"

BUILDDIR="$TOP_DIR/osx-release-dmg"
BUILDDIR_APPSTORE="$TOP_DIR/osx-release-appstore"

INSTALL_DIR="$TOP_DIR/install"
SDK="11.0"
JOBS=7

cd $TOP_DIR

do_openssl
# Only builds x86_64 binaries, hell knows why...
# do_mysql

cmake -B "$BUILDDIR" "$XCA_DIR" \
	-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
	-DCMAKE_PREFIX_PATH="$QT_DIR/lib/cmake;$INSTALL_DIR" \
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
	-DPROVISIONPROFILE="$TOP_DIR/XCA_AppStore_Provisioning.provisionprofile"

read xca_version < "$BUILDDIR_APPSTORE"/PKGVERSION.txt
cmake --build "$BUILDDIR_APPSTORE" -j$JOBS
productbuild --component "$BUILDDIR_APPSTORE/xca.app" /Applications \
    --sign "3rd Party Mac Developer Installer" "$BUILDDIR_APPSTORE/xca-${xca_version}-appstore.pkg"
