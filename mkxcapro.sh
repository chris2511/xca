#!/bin/sh

P=xca.pro

if [ -e Makefile ]; then
	make distclean
fi

echo "HEADERS = "`ls *.h`  >$P
echo "SOURCES = "`ls *.cpp` >>$P
echo "FORMS   = "`ls *.ui` >>$P
echo "TRANSLATIONS = xca_de.ts xca_es.ts" >>$P
