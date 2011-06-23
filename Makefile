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
INSTTARGET=$(patsubst %, install.%, $(INSTDIR))
APPTARGET=$(patsubst %, app.%, $(INSTDIR))

bindir=bin
DMGSTAGE=$(BUILD)/xca-$(VERSION)
MACTARGET=$(DMGSTAGE)-$(DARWIN)
APPDIR=$(DMGSTAGE)/xca.app/Contents

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

$(INSTTARGET): install.%: $(BUILD)/%/.build-stamp
	mkdir -p $(BUILD)/$*
	$(MAKE) -C $(BUILD)/$* -f $(TOPDIR)/$*/Makefile \
		VPATH=$(TOPDIR)/$* install

$(APPTARGET): app.%: $(BUILD)/%/.build-stamp
	mkdir -p $(BUILD)/$*
	$(MAKE) -C $(BUILD)/$* -f $(TOPDIR)/$*/Makefile \
		VPATH=$(TOPDIR)/$* APPDIR=$(APPDIR) app

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

install: xca$(SUFFIX) $(INSTTARGET)
	install -m 755 -d $(destdir)$(prefix)/$(bindir)
	install -m 755 xca $(destdir)$(prefix)/$(bindir)
	$(STRIP) $(destdir)$(prefix)/$(bindir)/xca

$(MACDEPLOYQT):

macdeployqt/macdeployqt:
	$(MAKE) -C macdeployqt

setup.exe: xca$(SUFFIX) misc/xca.nsi do.doc do.lang
	$(STRIP) xca$(SUFFIX)
	$(MAKENSIS) -DINSTALLDIR=$(INSTALL_DIR) -DQTDIR=$(QTDIR) \
		-DVERSION=$(VERSION) -DBDIR=$(BDIR) -DBUILD=$(BUILD) \
		-NOCD -V2 misc/xca.nsi

$(DMGSTAGE): xca$(SUFFIX) $(MACDEPLOYQT)
	rm -rf $(DMGSTAGE)
	mkdir -p $(DMGSTAGE)/xca.app/Contents/MacOS
	mkdir -p $(DMGSTAGE)/xca.app/Contents/Resources
	mkdir -p $(DMGSTAGE)/manual
	ln -s /Applications $(DMGSTAGE)
	install -m 644 COPYRIGHT $(DMGSTAGE)/COPYRIGHT.txt
	install -m 755 xca $(DMGSTAGE)/xca.app/Contents/MacOS
	$(STRIP) $(DMGSTAGE)/xca.app/Contents/MacOS/xca
	$(MAKE) $(APPTARGET)
	cp -r $(DMGSTAGE)/xca.app/Contents/Resources/*.html $(DMGSTAGE)/manual
	ln -s xca.html $(DMGSTAGE)/manual/index.html
	$(MACDEPLOYQT) $(DMGSTAGE)/xca.app
	tar zcf $(MACTARGET).tar.gz $(DMGSTAGE)

xca.dmg: $(MACTARGET).dmg

xca.app: $(DMGSTAGE)

$(MACTARGET).dmg: $(DMGSTAGE)
	hdiutil create -ov -srcfolder $< $@

trans:
	$(MAKE) -C lang po2ts
	lupdate-qt4 $(TOPDIR)/xca.pro
	$(MAKE) -C lang xca.pot

.PHONY: $(SUBDIRS) $(INSTDIR) xca.app setup.exe doc lang macdeployqt/macdeployqt $(DMGSTAGE)

doc lang headers: local.h

Local.mak local.h: configure
	./configure

