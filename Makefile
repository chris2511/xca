#
# Makefile for XCA
#
#####################################################################

TAG=RELEASE.$(TVERSION)
TARGET=xca-$(TVERSION)

export TOPDIR=$(shell pwd)
export VERSION=$(shell cat $(TOPDIR)/VERSION )
export BUILD=$(TOPDIR)/xca_build

sinclude Local.mak

SUBDIRS=lib widgets img
OBJECTS=$(patsubst %, $(BUILD)/%/.build-stamp, $(SUBDIRS))
INSTDIR=misc lang doc img
CLEANDIRS=lang doc ui img macdeployqt
HDRDIRS=lib widgets ui

bindir=bin
DMGSTAGE=$(BUILD)/xca-$(VERSION)
MACTARGET=$(DMGSTAGE)-$(DARWIN)

ifeq ($(SUFFIX), .exe)
all: setup$(SUFFIX)
else
ifneq ($(MACDEPLOYQT),)
all: $(MACTARGET).dmg
else
all: xca$(SUFFIX) do.doc do.lang
	@echo
	@echo "Ok, compilation was successful."
	@echo "Now do as root: 'make install'"
	@echo
endif
endif


xca$(SUFFIX): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(patsubst %,@%, $^) $(LIBS) -o $@

do.ui do.doc do.lang: do.%:
	mkdir -p $(BUILD)/$*
	$(MAKE) -C $(BUILD)/$* -f $(TOPDIR)/$*/Makefile VPATH=$(TOPDIR)/$* $*

headers: do.ui

$(BUILD)/%/.build-stamp: headers
	mkdir -p $(BUILD)/$*
	$(MAKE) DEP=yes -C $(BUILD)/$* -f $(TOPDIR)/$*/Makefile \
		VPATH=$(TOPDIR)/$*

clean:
	rm -rf $(BUILD)
	rm -f *~ xca$(SUFFIX) setup_xca*.exe $(MACTARGET).dmg $(MACTARGET).tar.gz
	rm -rf $(DMGSTAGE)

distclean: clean
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

$(MACDEPLOYQT):

macdeployqt/macdeployqt:
	$(MAKE) -C macdeployqt

setup.exe: xca$(SUFFIX) misc/xca.nsi do.doc do.lang
	$(STRIP) xca$(SUFFIX)
	$(MAKENSIS) -DINSTALLDIR=$(INSTALL_DIR) -DQTDIR=$(QTDIR) \
		-DVERSION=$(VERSION) -DBDIR=$(BDIR) -DBUILD=$(BUILD) \
		-NOCD -V2 misc/xca.nsi

xca.app: $(DMGSTAGE)

$(DMGSTAGE): xca$(SUFFIX) $(MACDEPLOYQT) do.doc do.lang
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
	$(MACDEPLOYQT) $(DMGSTAGE)/xca.app
	tar zcf $(MACTARGET).tar.gz $(DMGSTAGE)

xca.dmg: $(MACTARGET).dmg

$(MACTARGET).dmg: $(DMGSTAGE)
	hdiutil create -ov -srcfolder $< $@

trans:
	$(MAKE) -C lang po2ts
	lupdate-qt4 $(TOPDIR)/xca.pro
	$(MAKE) -C lang xca.pot

.PHONY: $(SUBDIRS) $(INSTDIR) xca.app setup.exe doc lang macdeployqt/macdeployqt

doc lang headers: local.h

Local.mak local.h: configure
	./configure

