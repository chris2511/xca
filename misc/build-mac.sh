#!/bin/sh -e

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
