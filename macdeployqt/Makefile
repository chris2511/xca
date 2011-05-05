
ifeq ($(TOPDIR),)
TOPDIR=..
endif

all: macdeployqt

macdeployqt: Makefile.qt main.cpp shared.cpp shared.h
	$(MAKE) -f Makefile.qt

Makefile.qt: macdeployqt.pro
	$(QMAKE) -spec macx-g++ -o $@ $<

clean:
	rm -f *.o Makefile.qt macdeployqt
distclean: clean

include $(TOPDIR)/Local.mak
