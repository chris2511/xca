#!/bin/sh

P=xca.pro

if [ -e Makefile ]; then
	make distclean
fi

echo -n "Creating $P ..."

echo "HEADERS = "`ls *.h` `ls lib/*.h`  >$P
echo "SOURCES = "`ls *.cpp` `ls lib/*.cpp` >>$P
echo "FORMS = "`ls *.ui` >>$P
echo "TRANSLATIONS = "`ls xca_??.ts` >>$P
echo "TARGET = xca" >>$P

echo "  done"


