VERSION=0.1.1
GCC=c++
INC=-I$(QTDIR)/include
LPATH=-L$(QTDIR)/lib
LIBS=-lqt -lcrypto -ldb_cxx
MOC=$(QTDIR)/bin/moc
UIC=$(QTDIR)/bin/uic

OBJS=NewKeyDlg_UI.o NewKeyDlg_UI_MOC.o \
     KeyDetailDlg_UI.o KeyDetailDlg_UI_MOC.o \
     MainWindow_UI.o MainWindow_UI_MOC.o \
     PassRead_UI.o PassRead_UI_MOC.o \
     PassWrite_UI.o PassWrite_UI_MOC.o \
     ExportKey_UI.o ExportKey_UI_MOC.o \
     ExportKey.o ExportKey_MOC.o \
     MainWindow.o MainWindow_MOC.o \
     RSAkey.o RSAkey_MOC.o \
     KeyDB.o KeyDB_MOC.o

all: $(OBJS) xca
re: clean all

MainWindow.h: MainWindow_UI.h KeyDetailDlg_UI.h \
	      PassRead_UI.h PassWrite_UI.h ExportKey_UI.h
NewKeyDlg.h: NewKeyDlg_UI.h

%.o: %.cpp
	$(GCC) -c $(INC) $<

%_MOC.cpp: %.h
	$(MOC) $< -o $@

%_UI.h: %.ui
	$(UIC) -o $@ $<

%_UI.cpp: %_UI.h %.ui
	$(UIC) -o $@ -i $^

xca: main.cpp $(OBJS)
	$(GCC) $(INC) $(LPATH) $(LIBS) -DVER=\"$(VERSION)\" main.cpp $(OBJS) -o xca

clean:
	rm -rf *_MOC.cpp *_UI.h *_UI.cpp *~ *.o xca

dist: clean
	(cd ..; tar zcf xca-$(VERSION).tar.gz xca;)
	
install: xca
	install -m 755 -o root -g root xca /usr/bin
