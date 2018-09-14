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
export QTDIR=/Users/chris/Qt/5.9.1/clang_64
export CFLAGS="-mmacosx-version-min=10.10"
export EXTRA_VERSION="-Yosemite"

if test -f build-libs; then
  do_libtool
  do_openssl
fi

XCA_BUILD="xca-macbuild"
# configure XCA and build the DMG file
rm -rf "$XCA_BUILD"
mkdir -p "$XCA_BUILD"
cd "$XCA_BUILD"

export CPPFLAGS="$CFLAGS -I${INSTALL_DIR}/include -F$QTDIR"
export CXXFLAGS="$CFLAGS -F$QTDIR"
export LDFLAGS="-L${INSTALL_DIR}/lib"

(cd $XCA_DIR && ./bootstrap)
$XCA_DIR/configure --with-openssl="$INSTALL_DIR" --with-qt=$QTDIR
make -j5
cp *.dmg ..
