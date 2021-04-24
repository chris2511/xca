#!/bin/sh -e

do_openssl()
{
set -x
read openssl < "`dirname $0`/../OpenSSL.version"
test -f "$openssl".tar.gz || curl https://www.openssl.org/source/"$openssl".tar.gz > "$openssl".tar.gz
tar zxf "$openssl".tar.gz
(cd $openssl
 ./Configure darwin64-x86_64-cc shared --prefix=$INSTALL_DIR $CFLAGS
 #./config shared --prefix=$INSTALL_DIR
 make && make install_sw
)
chmod 755 $INSTALL_DIR/lib/*.dylib
}

do_libtool()
{(
read libtool < "`dirname $0`/../Libtool.version"
test -f "$libtool".tar.gz || curl http://ftp.gnu.org/gnu/libtool/"$libtool".tar.gz > "$libtool".tar.gz
tar zxf "$libtool".tar.gz
cd "$libtool"
#export CFLAGS="-arch i386"
./configure --prefix ${INSTALL_DIR}
make && make install
)}

XCA_DIR="`dirname $0`"
XCA_DIR="`cd $XCA_DIR/.. && pwd`"

# define the installation dir and the path to the new library
# it will be installed locally in the home directory
export INSTALL_DIR="`pwd`"/install
export DYLD_LIBRARY_PATH=$INSTALL_DIR/lib
export CPPFLAGS="$CPPFLAGS -I${INSTALL_DIR}/include"
export LDFLAGS="-L${INSTALL_DIR}/lib"

export CFLAGS="-mmacosx-version-min=10.13"

if test -f build-libs; then
  mkdir -p "$INSTALL_DIR"
  do_libtool
  do_openssl
fi
unset CFLAGS

XCA_DIR="`dirname $0`"
XCA_DIR="`cd $XCA_DIR/.. && pwd`"

XCA_BUILD="xca-macbuild"
#rm -rf "$XCA_BUILD"
mkdir -p "$XCA_BUILD"
cd "$XCA_BUILD"

(cd $XCA_DIR && ./bootstrap)
$XCA_DIR/configure --with-macos-version=10.13 --with-openssl="$INSTALL_DIR"
make -j5
cp *.dmg ..

DMG=xca-2.3.0.139-Yosemite.dmg
