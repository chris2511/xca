#
# Makefile for XCA
#
#####################################################################

TAG=RELEASE.$(TVERSION)
TARGET=xca-$(TVERSION)

export VERSION=$(shell cat $(TOPDIR)/VERSION )
export TOPDIR=$(shell pwd)

sinclude Local.mak

SUBDIRS=lib widgets img
OBJECTS=$(patsubst %, %/target.obj, $(SUBDIRS))
INSTDIR=misc lang doc img
CLEANDIRS=lang doc ui img macdeployqt
HDRDIRS=lib widgets ui

ifneq ($(LDFLAGS),)
GCCLDFLAGS="-Wl,`echo $(LDFLAGS) |sed 's/ /,/g'`"
endif

bindir=bin

all: headers xca$(SUFFIX) doc lang
	@echo -e "\n\n\nOk, compilation was successfull. \nNow do as root: 'make install'\n"

xca.o: $(OBJECTS)
	$(LD) $(LDFLAGS) $(OBJECTS) -r -o $@ $(SLIBS)

xca$(SUFFIX): xca.o
	$(CC) $(CFLAGS) $(GCCLDFLAGS) $< $(LIBS) -o $@

doc: 
	$(MAKE) -C doc
lang: 
	$(MAKE) -C lang

headers:
	$(MAKE) -C ui $@

pheaders: headers
	for d in $(HDRDIRS); do $(MAKE) -C $$d pheaders; done

%/target.obj: headers
	$(MAKE) DEP=yes -C $* target.obj

clean:
	for x in $(SUBDIRS) $(CLEANDIRS); do $(MAKE) -C $${x} clean; done
	rm -f *~ xca$(SUFFIX) xca.o setup_xca*.exe
	rm -rf dmgstage

distclean:
	for x in $(SUBDIRS) $(CLEANDIRS); do $(MAKE) -C $${x} distclean; done
	rm -f conftest conftest.log local.h Local.mak *~

dist:
	test ! -z "$(TVERSION)"
	git archive --format=tar --prefix=$(TARGET)/ $(TAG) | \
		gzip -9 > $(TARGET).tar.gz

snapshot:
	HASH=$$(git rev-parse HEAD) && \
	git archive --format=tar --prefix=xca-$${HASH}/ HEAD | \
		gzip -9 > xca-$${HASH}.tar.gz

install: xca$(SUFFIX)
	install -m 755 -d $(destdir)$(prefix)/$(bindir)
	install -m 755 xca $(destdir)$(prefix)/$(bindir)
	$(STRIP) $(destdir)$(prefix)/$(bindir)/xca
	for d in $(INSTDIR); do \
	  $(MAKE) -C $$d install; \
	done

macdeployqt/macdeployqt:
	$(MAKE) -C macdeployqt

setup.exe: xca$(SUFFIX) misc/xca.nsi doc lang
	$(MAKE) -C lang
	$(STRIP) xca$(SUFFIX)
	$(MAKENSIS) -DINSTALLDIR=$(INSTALL_DIR) -DQTDIR=$(QTDIR) \
		-DVERSION=$(VERSION) -DBDIR=$(BDIR) -NOCD -V2 misc/xca.nsi

DMGSTAGE=xca-$(VERSION)

xca.app: $(DMGSTAGE)

$(DMGSTAGE): xca$(SUFFIX)
	rm -rf $(DMGSTAGE)
	mkdir -p $(DMGSTAGE)/xca.app/Contents/MacOS
	mkdir -p $(DMGSTAGE)/xca.app/Contents/Resources
	mkdir -p $(DMGSTAGE)/manual
	ln -s /Applications $(DMGSTAGE)
	install -m 644 COPYRIGHT $(DMGSTAGE)/COPYRIGHT.txt
	install -m 755 xca $(DMGSTAGE)/xca.app/Contents/MacOS
	$(STRIP) $(DMGSTAGE)/xca.app/Contents/MacOS/xca
	for d in $(INSTDIR); do \
          $(MAKE) -C $$d APPDIR=$(TOPDIR)/$(DMGSTAGE)/xca.app/Contents app; \
        done
	cp -r $(DMGSTAGE)/xca.app/Contents/Resources/*.html $(DMGSTAGE)/manual
	ln -s xca.html $(DMGSTAGE)/manual/index.html
	SYSROOT=$(SYSROOT) OTOOL=$(OTOOL) NAME_TOOL=$(NAME_TOOL)\
		 $(MACDEPLOYQT) $(DMGSTAGE)/xca.app
	tar zcf $(DMGSTAGE)-SnowLeopard.tar.gz $(DMGSTAGE)

xca.dmg: xca-$(VERSION)-SnowLeopard.dmg

xca-$(VERSION)-SnowLeopard.dmg: $(DMGSTAGE)
	hdiutil create -ov -srcfolder $< $@

trans:
	$(MAKE) -C lang po2ts
	lupdate-qt4 $(TOPDIR)/xca.pro
	$(MAKE) -C lang xca.pot

.PHONY: $(SUBDIRS) $(INSTDIR) xca.app setup.exe doc lang macdeployqt/macdeployqt

doc lang headers: local.h

Local.mak local.h: configure
	./configure

