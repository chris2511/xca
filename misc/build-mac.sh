#!/bin/sh -e

do_openssl()
{
openssl="openssl-1.0.1j"
test -f "$openssl".tar.gz || curl http://www.openssl.org/source/"$openssl".tar.gz > "$openssl".tar.gz
tar zxf "$openssl".tar.gz
(cd $openssl
 #./Configure darwin64-x86_64-cc shared --prefix=$INSTALL_DIR
 ./config shared --prefix=$INSTALL_DIR
 make && make install
)
chmod 755 $INSTALL_DIR/lib/*.dylib
}

do_libtool()
{(
libtool="libtool-2.2.6b"
test -f "$libtool".tar.gz || curl http://ftp.gnu.org/gnu/libtool/"$libtool".tar.gz > "$libtool".tar.gz
tar zxf "$libtool".tar.gz
cd "$libtool"
export CFLAGS="-arch i386"
./configure --prefix ${INSTALL_DIR}
make && make install
)}


# define the installation dir and the path to the new library
# it will be installed locally in the home directory
export INSTALL_DIR="`pwd`"/install
export DYLD_LIBRARY_PATH=$INSTALL_DIR/lib
export QTDIR=$HOME/src/install/Qt485

XCA_DIR="`dirname $0`"
XCA_DIR="`cd $XCA_DIR/.. && pwd`"
doc=$XCA_DIR/doc/xca-doc.tgz
test -f $doc || curl http://git.hohnstaedt.de/xca-doc.tgz > $doc

do_libtool
do_openssl

# configure XCA and build the DMG file
rm -rf xca-macbuild
mkdir -p xca-macbuild/doc
cd xca-macbuild

export CXXFLAGS="-arch i386 -I${INSTALL_DIR}/include -L${INSTALL_DIR}/lib"

(cd $XCA_DIR && ./bootstrap)
$XCA_DIR/configure --with-openssl="$INSTALL_DIR" --with-qt="$QTDIR"
make -j5 && make xca.dmg
