#
# $Id$
#
#####################################################################

TAG=$(shell echo "V.$(TVERSION)" |sed "s/\./_/g" )
TARGET=xca-$(TVERSION)

export TOPDIR=$(shell pwd)

SUBDIRS=lib widgets view ui
OBJECTS=$(patsubst %, %/target.obj, $(SUBDIRS))
INSTDIR=img misc lang doc

bindir=bin

all: headers xca doc
re: clean all

xca: $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o xca
	#$(CC) $(CPPFLAGS) ../mingw/qt/lib/qt-mt230nc.lib ../mingw/qt/lib/qtmain.lib main.cpp -o main
	@echo -e "\n\n\nOk, compilation was successfull. \nNow do as root: 'make install'\n"

headers:
	$(MAKE) -C ui $@

%/target.obj: headers
	$(MAKE) DEP=yes -C $* target.obj

clean:
	for x in $(SUBDIRS); do \
	  $(MAKE) -C $${x} clean; \
	done
	rm -f *~ xca 

distclean: clean	
	rm -f Local.mak

dist: 
	test ! -z "$(TVERSION)"
	rm -rf $(TARGET) 
	cvs export -r $(TAG) -d $(TARGET) xca && 
	(cd $(TARGET) && \
	./mkxcapro.sh && lrelease xca.pro || echo 'lrelease not found !!' && \
	cat rpm/xca.spec |sed s/VERSION/$(TVERSION)/g >rpm/$(TARGET)-1.spec && \
	cat lib/base.h.in |sed s/MY_VERSION/$(TVERSION)/g >lib/base.h && \
	cat doc/xca.man |sed s/MY_VERSION/$(TVERSION)/g >doc/xca.1 && \
	cat misc/xca.nsi |sed s/VERSION/$(TVERSION)/g >misc/$(TARGET).nsi && \
	rm -rf misc/xca.nsi rpm/xca.spec && \
	cd doc && linuxdoc -B html xca.sgml || echo "no linuxdoc found -> continuing"; ) && \
	tar zcf $(TARGET).tar.gz $(TARGET) 
	#rm -rf ../$(TARGET)
	
install: xca
	$(STRIP) xca
	install -m 755 -d $(destdir)$(prefix)/$(bindir)
	install -m 755 xca $(destdir)$(prefix)/$(bindir)
	for d in $(INSTDIR); do \
	  $(MAKE) -C $$d install; \
	done

.PHONY: $(SUBDIRS)

Local.mak: configure
	./configure

sinclude Local.mak
