VERSION=0.1.5
TARGET=xca-$(VERSION)
GCC=c++
INC=-I$(QTDIR)/include
LPATH=-L$(QTDIR)/lib -Llib
LIBS=-lqt -lcrypto -ldb_cxx  -lpki -lxcadb
MOC=$(QTDIR)/bin/moc
UIC=$(QTDIR)/bin/uic

OBJS=NewKey_UI.o NewKey_UI_MOC.o \
     KeyDetail_UI.o KeyDetail_UI_MOC.o \
     ReqDetail_UI.o ReqDetail_UI_MOC.o \
     MainWindow_UI.o MainWindow_UI_MOC.o \
     PassRead_UI.o PassRead_UI_MOC.o \
     PassWrite_UI.o PassWrite_UI_MOC.o \
     ExportKey_UI.o ExportKey_UI_MOC.o \
     NewX509Req_UI.o NewX509Req_UI_MOC.o \
     ExportKey.o ExportKey_MOC.o \
     MainWindow.o MainWindow_MOC.o \
     MainWindowKeys.o MainWindowX509Req.o 

all: libs $(OBJS) xca
re: clean all

MainWindow.h: MainWindow_UI.h KeyDetail_UI.h \
	      PassRead_UI.h PassWrite_UI.h ExportKey_UI.h \
	      NewX509Req_UI.h NewKey_UI.h ReqDetail_UI.h

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

libs:
	make -C lib all

clean:
	make -C lib clean
	rm -rf *_MOC.cpp *_UI.h *_UI.cpp *~ *.o xca

dist: 
	cvs export -r HEAD -d $(TARGET) xca
	tar zcf $(TARGET).tar.gz $(TARGET)
	rm -rf $(TARGET)
	
install: xca
	install -m 755 -o root -g root xca /usr/bin
