#!/bin/sh

P=xca.pro
W=win.bat

if [ -e Makefile ]; then
	make distclean
fi

FORMS=`ls *.ui`
SOURCES="`ls *.cpp` `ls lib/*.cpp`"
HEADERS="`ls *.h` `ls lib/*.h` "

echo "HEADERS=$HEADERS" >$P
echo "SOURCES=$SOURCES" >>$P
echo "FORMS=$FORMS" >>$P
echo "TRANSLATIONS="`ls xca_??.ts` >>$P
echo "TARGET=xca" >>$P

rm -f $W

for F in $FORMS; do 
	B=`echo $F |cut -d "." -f 1`
	echo uic -o ${B}.h ${F} >> $W
	echo uic -o ${B}.cpp -impl ${B}.h ${F} >> $W
done

for F in $HEADERS; do
	grep Q_OBJECT $F >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		B=`echo $F |cut -d "." -f 1`
		echo moc -o moc_${B}.cpp ${F} >> $W
	fi
done
