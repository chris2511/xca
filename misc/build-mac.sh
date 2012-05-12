#!/bin/sh -e

do_openssl()
{
openssl="openssl-1.0.1c"
test -f "$openssl".tar.gz || curl http://openssl.org/source/"$openssl".tar.gz > "$openssl".tar.gz
tar zxf "$openssl".tar.gz
(cd $openssl
 #./Configure darwin64-x86_64-cc shared --prefix=$OPENSSLINSTALLDIR
 ./config shared --prefix=$OPENSSLINSTALLDIR
 make && make install
)
chmod 755 $OPENSSLINSTALLDIR/lib/*.dylib
 
}

# define the installation dir and the path to the new library
# it will be installed locally in the home directory
export OPENSSLINSTALLDIR=$HOME/instopenssl
export DYLD_LIBRARY_PATH=$OPENSSLINSTALLDIR/lib
#export QTDIR=$HOME/QtSDK/Desktop/Qt/4.8.1/gcc

XCA_DIR="`dirname $0`"
XCA_DIR="`cd $XCA_DIR/.. && pwd`"
doc=$XCA_DIR/doc/xca-doc.tgz
test -f $doc || curl http://git.hohnstaedt.de/xca-doc.tgz > $doc

do_openssl

# configure XCA and build the DMG file
rm -rf xca-macbuild
mkdir xca-macbuild
cd xca-macbuild

$XCA_DIR/configure $OPENSSLINSTALLDIR
make -j5 xca.dmg
