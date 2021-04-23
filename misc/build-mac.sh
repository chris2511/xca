#!/bin/sh -e

XCA_DIR="`dirname $0`"
XCA_DIR="`cd $XCA_DIR/.. && pwd`"

export CFLAGS="-mmacosx-version-min=10.13"
export EXTRA_VERSION="-High-Sierra"

XCA_BUILD="xca-macbuild"
#rm -rf "$XCA_BUILD"
mkdir -p "$XCA_BUILD"
cd "$XCA_BUILD"

(cd $XCA_DIR && ./bootstrap)
$XCA_DIR/configure
make -j5
cp *.dmg ..

DMG=xca-2.3.0.139-Yosemite.dmg
