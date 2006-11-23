#
# Makefile for XCA
#
#####################################################################

TAG=RELEASE.$(TVERSION)
TARGET=xca-$(TVERSION)

export TOPDIR=$(shell pwd)

sinclude Local.mak

SUBDIRS=lib widgets img
OBJECTS=$(patsubst %, %/target.obj, $(SUBDIRS))
INSTDIR=misc lang doc
CLEANDIRS=lang doc ui img

bindir=bin

all: headers xca$(SUFFIX) docs
	@echo -e "\n\n\nOk, compilation was successfull. \nNow do as root: 'make install'\n"
re: clean all

xca.o: $(OBJECTS)
	$(LD) $(OBJECTS) $(SLIBS) -r -o $@

xca$(SUFFIX): xca.o
	$(CC) $(LDFLAGS) $(CFLAGS) $< $(LIBS) -o $@

docs:
	$(MAKE) -C doc
headers:
	$(MAKE) -C ui $@

%/target.obj: headers
	$(MAKE) DEP=yes -C $* target.obj

clean:
	for x in $(SUBDIRS) $(CLEANDIRS); do $(MAKE) -C $${x} clean; done
	rm -f *~ xca$(SUFFIX) xca.o

distclean: clean
	rm -f Local.mak conftest conftest.log xca.pro

dist:
	test ! -z "$(TVERSION)"
	rm -rf $(TARGET)
	exit 1
	git checkout -r $(TAG) -d $(TARGET) xca && \
	(cd $(TARGET) && \
	./mkxcapro.sh && lrelease xca.pro || echo 'lrelease not found !!' && \
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

xca.app: xca docs
	rm -rf xca.app
	mkdir -p xca.app/Contents/MacOS
	mkdir -p xca.app/Contents/Resources
	install -m 755 xca xca.app/Contents/MacOS
	$(STRIP) xca.app/Contents/MacOS/xca
	for d in $(INSTDIR); do \
	  $(MAKE) -C $$d APPDIR=$(TOPDIR)/xca.app/Contents app; \
	done

xca.dmg: xca.app
	test -x hdiutil
	hdiutil create -ov -srcfolder $< $@

setup.exe: xca$(SUFFIX) misc/xca.nsi docs
	$(MAKE) -C lang
	$(STRIP) xca$(SUFFIX)
	$(MAKENSIS) /DOPENSSL=$(OPENSSLDIR_DOS) /DQTDIR=$(QTDIR_DOS) \
		/DVERSION=$(VERSION) /NOCD /V2 misc/xca.nsi

.PHONY: $(SUBDIRS) xca.app setup.exe

Local.mak: configure
	./configure

