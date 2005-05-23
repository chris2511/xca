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
CLEANDIRS=lang doc 

bindir=bin

all: headers xca docs
re: clean all

xca.o: $(OBJECTS)
	$(LD) $(LDFLAGS) $(OBJECTS) $(SLIBS) -r -o $@

xca: xca.o
	$(CC) $(LDFLAGS) $< $(LIBS) -o $@
	@echo -e "\n\n\nOk, compilation was successfull. \nNow do as root: 'make install'\n"

docs:
	$(MAKE) -C doc
headers:
	$(MAKE) -C ui $@

%/target.obj: headers
	$(MAKE) DEP=yes -C $* target.obj

clean:
	for x in $(SUBDIRS) $(CLEANDIRS); do $(MAKE) -C $${x} clean; done
	rm -f *~ xca xca.o

distclean: clean	
	rm -f Local.mak conftest conftest.log

dist: 
	test ! -z "$(TVERSION)"
	rm -rf $(TARGET) 
	cvs export -r $(TAG) -d $(TARGET) xca && \
	(cd $(TARGET) && \
	./mkxcapro.sh && lrelease xca.pro || echo 'lrelease not found !!' && \
	cat misc/xca.nsi |sed s/VERSION/$(TVERSION)/g >misc/$(TARGET).nsi && \
	cd doc && linuxdoc -B html xca.sgml || echo "no linuxdoc found -> continuing"; ) && \
	tar zcf $(TARGET).tar.gz $(TARGET) && \
	(cd $(TARGET) && dpkg-buildpackage -rfakeroot )
	#rm -rf ../$(TARGET)

install: xca
	install -m 755 -d $(destdir)$(prefix)/$(bindir)
	install -m 755 xca $(destdir)$(prefix)/$(bindir)
	$(STRIP) $(destdir)$(prefix)/$(bindir)/xca
	
	for d in $(INSTDIR); do \
	  $(MAKE) -C $$d install; \
	done

xca.app: xca
	rm -rf xca.app
	mkdir -p xca.app/Contents/MacOS
	mkdir -p xca.app/Contents/Resources
	install -m 755 xca xca.app/Contents/MacOS
	$(STRIP) xca.app/Contents/MacOS/xca
	for d in $(INSTDIR); do \
	  $(MAKE) -C $$d APPDIR=$(TOPDIR)/xca.app/Contents app; \
	done

xca.dmg: xca.app
	hdiutil create -ov -srcfolder $< $@

.PHONY: $(SUBDIRS) xca.app

Local.mak: configure
	./configure

sinclude Local.mak
