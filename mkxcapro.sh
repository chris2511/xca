#!/bin/sh

P=xca.pro

if [ -e Makefile ]; then
	make distclean
fi

echo "HEADERS = "`ls *.h`  >$P
echo "SOURCES = "`ls *.cpp` >>$P
echo "FORMS   = "`ls *.ui` >>$P
echo "TRANSLATIONS = "`ls xca_??.ts` >>$P
echo "TARGET = xca" >>$P
