VERSION=0.2.1
TAG=$(shell echo "V.$(VERSION)" |sed "s/\./_/g" )
TARGET=xca-$(VERSION)

PREFIX=/usr/local
GCC=g++
CFLAGS=-Wall -g

###########################
# LFS

QTDIR=/usr/lib/qt
export INC=-I$(QTDIR)/include 
LPATH=-L$(QTDIR)/lib -Llib
LIBS=-lqt -lcrypto -ldb_cxx -lxcadb -lpki
MOC=$(QTDIR)/bin/moc
UIC=$(QTDIR)/bin/uic

###########################
#  debian woody

#export INC=-I/usr/include/qt 
#LPATH=-Llib
#LIBS=-lqt -lcrypto -ldb3_cxx -lxcadb -lpki
#MOC=/usr/bin/moc
#UIC=/usr/bin/uic

###################################

OBJS=NewKey_UI.o NewKey_UI_MOC.o \
     KeyDetail_UI.o KeyDetail_UI_MOC.o \
     ReqDetail_UI.o ReqDetail_UI_MOC.o \
     MainWindow_UI.o MainWindow_UI_MOC.o \
     PassRead_UI.o PassRead_UI_MOC.o \
     PassWrite_UI.o PassWrite_UI_MOC.o \
     ExportKey_UI.o ExportKey_UI_MOC.o \
     NewX509Req_UI.o NewX509Req_UI_MOC.o \
     NewX509_UI.o NewX509_UI_MOC.o \
     NewX509_1_UI.o NewX509_1_UI_MOC.o \
     NewX509_2_UI.o NewX509_2_UI_MOC.o \
     NewX509.o NewX509_MOC.o \
     CertDetail_UI.o CertDetail_UI_MOC.o \
     ExportKey.o ExportKey_MOC.o \
     MainWindow.o MainWindow_MOC.o \
     MainWindowKeys.o MainWindowX509Req.o MainWindowX509.o \
     main.o

all: libs $(OBJS) xca

re: clean all

MainWindow.h: MainWindow_UI.h KeyDetail_UI.h \
	      PassRead_UI.h PassWrite_UI.h ExportKey_UI.h \
	      NewX509Req_UI.h NewKey_UI.h ReqDetail_UI.h \
	      NewX509_UI.h CertDetail_UI.h NewX509_1_UI.h NewX509_2_UI.h

%.o: %.cpp
	$(GCC) $(CFLAGS) -c $(INC) -DVER=\"$(VERSION)\" -DPREFIX=\"$(PREFIX)\" $<

%_MOC.cpp: %.h
	$(MOC) $< -o $@

%_UI.h: %.ui
	$(UIC) -o $@ $<

%_UI.cpp: %_UI.h %.ui
	$(UIC) -o $@ -i $^

xca: $(OBJS) lib/libxcadb.a lib/libpki.a
	$(GCC) $(CFLAGS) $(INC) $(LPATH) $(OBJS) $(LIBS) -o xca

libs:
	make -C lib all VERSION=$(VERSION) PREFIX=$(PREFIX)

clean:
	make -C lib clean
	rm -rf *_MOC.cpp *_UI.h *_UI.cpp *~ *.o xca

dist: 
	rm -rf ../$(TARGET)
	cvs export -r $(TAG) -d ../$(TARGET) xca
	rcs2log >> ../$(TARGET)/CHANGELOG 
	(cd ..; tar zcf $(TARGET).tar.gz $(TARGET) )
	rm -rf ../$(TARGET)
	
install: xca
	install -m 755 -o root -g root xca $(DESTDIR)$(PREFIX)/bin
	install -m 755 -o root -g root -d $(DESTDIR)$(PREFIX)/share/xca
	install -m 644 -o root -g root *.png $(DESTDIR)$(PREFIX)/share/xca
	
