#!/bin/sh

P=xca.pro
W1=win.bat
W=win.tmp

if [ -e Makefile ]; then
	make distclean
fi

echo -n "Creating $P ..."
FORMS=`ls *.ui`
HEADERS="`ls *.h` `ls lib/*.h` "

echo "HEADERS = "`ls *.h` `ls lib/*.h`  >$P
echo "SOURCES = "`ls *.cpp` `ls lib/*.cpp` >>$P
echo "FORMS = "`ls *.ui` >>$P
echo "TRANSLATIONS = "`ls xca_??.ts` >>$P
echo "TARGET = xca" >>$P
echo "DEFINES += QT_DLL QT_THREAD_SUPPORT" >>$P
echo "CONFIG = qt warn_on release" >>$P
echo "TEMPLATE = app" >> $P


echo "  done"


echo -n "Creating $W ..."
rm -f $W

for F in $FORMS; do 
	B=`echo $F |cut -d "." -f 1`
	echo uic -o ${B}.h ${F} >> $W
	echo uic -o ${B}.cpp -impl ${B}.h ${F} >> $W
done

for F in $HEADERS; do
	grep Q_OBJECT $F >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		B=`basename $F |cut -d "." -f 1`
		C=`dirname $F`/
		if [ "$C" == "./" ]; then C=""; fi
		echo moc -o ${C}moc_${B}.cpp ${F} >> $W
	fi
done
cat $W |perl -e 'while(<STDIN>){chomp;print"$_\r\n";}' >$W1
rm -f $W
echo "  done"
