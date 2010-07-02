#!/bin/sh -e

ENGINE_DIR="engine_pkcs11-0.1.8"
ENGINE_GZ="${ENGINE_DIR}".tar.gz
ENGINE_DL="http://www.opensc-project.org/files/engine_pkcs11/${ENGINE_GZ}"

LIBP11_DIR="libp11-0.2.7"
LIBP11_GZ="${LIBP11_DIR}".tar.gz
LIBP11_DL="http://www.opensc-project.org/files/libp11/${LIBP11_GZ}"

XCA=xca

unpack() {
  eval "dir=\${$1_DIR} gz=\${$1_GZ} dl=\${$1_DL}"
  test -f "$gz" || curl "$dl" -o "$gz"
  rm -rf "$dir"
  echo "Building '$dir'"
  tar -zxf "$gz"
  cd "$dir"
}

export INSTALL_DIR=`pwd`/install

### Libp11
(
unpack LIBP11
./configure --prefix ${INSTALL_DIR} --enable-shared=no
make && make install
)

### Engine PKCS#11
(
unpack ENGINE
CFLAGS="-I${INSTALL_DIR}/include" LDFLAGS="-L${INSTALL_DIR}/lib" \
  LIBP11_CFLAGS="${CFLAGS}" LIBP11_LIBS="-lp11 -lltdl -lcrypto" PKG_CONFIG=: \
  ./configure --prefix ${INSTALL_DIR}

make && make install
cp ${INSTALL_DIR}/lib/engine/engine_pkcs11.so "$XCA"
)

# XCA
(
cd $XCA
cp misc/Local.mak.mac-native Local.mak
echo "#define VER \"`cat VERSION`\"" >local.h
make -j5
if test ! -f doc/xca-1.html; then
  curl http://git.hohnstaedt.de/xca-doc.tgz | tar -C doc -zxf -
fi
make xca.dmg
)
