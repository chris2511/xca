#!/bin/sh

P=xca.pro

if [ -e Makefile ]; then
	make distclean
fi

echo -n "Creating $P ..."

echo "HEADERS = "`ls lib/*.h` `ls widgets/*.h`  >$P
echo "SOURCES = "`ls lib/*.cpp` `ls widgets/*.cpp` >>$P
echo "FORMS = "`ls ui/*.ui` >>$P
echo "TRANSLATIONS = "`ls lang/xca_??.ts` >>$P
echo "TARGET = xca" >>$P

echo "  done"


