#
# Makefile for XCA
#
#####################################################################

TAG=RELEASE.$(TVERSION)
TARGET=xca-$(TVERSION)
MAKEFLAGS += -rR

export BUILD=$(shell pwd)

ifneq ($(MAKECMDGOALS), distclean)
ifneq ($(MAKECMDGOALS), clean)
ifneq ($(MAKECMDGOALS), dist)
include Local.mak
endif
endif
endif

VPATH=$(TOPDIR)
SUBDIRS=lib widgets img
OBJECTS=$(patsubst %, %/.build-stamp, $(SUBDIRS))
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

ifeq ($(MAKECMDGOALS),)
MAKEFLAGS += -s
PRINT=echo
else
PRINT=:
endif
export PRINT

ifneq ($(TOPDIR), $(BUILD))
do.ui: clean_topdir
clean_topdir:
	$(MAKE) -C $(TOPDIR) clean
endif

xca$(SUFFIX): $(OBJECTS)
	@$(PRINT) "  LINK   $@"
	$(CC) $(CFLAGS) $(LDFLAGS) $(patsubst %,@%, $^) $(LIBS) -o $@

do.ui do.doc do.lang: do.%:
	mkdir -p $*
	$(MAKE) -C $* -f $(TOPDIR)/$*/Makefile VPATH=$(TOPDIR)/$* $*

headers: do.ui

%/.build-stamp: headers
	mkdir -p $*
	$(MAKE) -C $* -f $(TOPDIR)/$*/Makefile \
		VPATH=$(TOPDIR)/$*

$(INSTTARGET): install.%: %/.build-stamp
	mkdir -p $*
	$(MAKE) -C $* -f $(TOPDIR)/$*/Makefile \
		VPATH=$(TOPDIR)/$* install

$(APPTARGET): app.%: %/.build-stamp
	mkdir -p $*
	$(MAKE) -C $* -f $(TOPDIR)/$*/Makefile \
		VPATH=$(TOPDIR)/$* APPDIR=$(APPDIR) app

clean:
	find lib widgets img -name "*.o" | xargs rm -f
	find lib widgets img -name ".build-stamp" | xargs rm -f
	find lib widgets -name "moc_*.cpp" | xargs rm -f
	rm -f ui/ui_*.h lang/xca_*.qm doc/*.html doc/xca.1.gz img/imgres.cpp
	rm -f lang/*.xml
	rm -f *~ xca$(SUFFIX) setup_xca*.exe
	rm -rf xca-*

distclean: clean
	rm -f conftest conftest.log local.h Local.mak *~ */.depend

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

setup.exe: xca$(SUFFIX) do.doc do.lang
setup.exe: misc/xca.nsi
	$(STRIP) xca$(SUFFIX)
	$(MAKENSIS) -DINSTALLDIR=$(INSTALL_DIR) -DQTDIR=$(QTDIR) \
		-DVERSION=$(VERSION) -DBDIR=$(BDIR) -DTOPDIR=$(TOPDIR)\
		-NOCD -V2 $<

$(DMGSTAGE): xca$(SUFFIX) $(MACDEPLOYQT)
	rm -rf $(DMGSTAGE)
	mkdir -p $(DMGSTAGE)/xca.app/Contents/MacOS
	mkdir -p $(DMGSTAGE)/xca.app/Contents/Resources
	mkdir -p $(DMGSTAGE)/manual
	ln -s /Applications $(DMGSTAGE)
	install -m 644 $(TOPDIR)/COPYRIGHT $(DMGSTAGE)/COPYRIGHT.txt
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

do.doc do.lang headers: local.h

Local.mak local.h: $(TOPDIR)/configure
	$(TOPDIR)/configure

