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
ifeq ($(TOPDIR),)
TOPDIR=.
endif

VPATH=$(TOPDIR)
SUBDIRS=lib widgets img misc
OBJECTS=$(patsubst %, %/.build-stamp, $(SUBDIRS))
INSTDIR=misc lang doc img
INSTTARGET=$(patsubst %, install.%, $(INSTDIR))
APPTARGET=$(patsubst %, app.%, $(INSTDIR))

DMGSTAGE=$(BUILD)/xca-$(VERSION)
MACTARGET=$(DMGSTAGE)${EXTRA_VERSION}
APPDIR=$(DMGSTAGE)/xca.app/Contents
OSSLSIGN_OPT=sign -pkcs12 "$(HOME)"/Christian_Hohnstaedt.p12 -askpass \
	-n "XCA $(VERSION)" -i https://hohnstaedt.de/xca \
	-t http://timestamp.comodoca.com -h sha2

ifeq ($(SUFFIX), .exe)
all: setup$(SUFFIX) xca-portable.zip
export CFLAGS_XCA_DB_STAT=-mconsole
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
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(patsubst %,@%, $^) $(LIBS) -o $@

do.ui do.doc do.lang do.misc: do.%:
	mkdir -p $*
	$(MAKE) -C $* -f $(TOPDIR)/$*/Makefile VPATH=$(TOPDIR)/$* $*

headers: do.ui commithash.h

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
	find lib widgets img misc  -name "*.o" \
				-o -name ".build-stamp" \
				-o -name ".depend" \
				-o -name "moc_*.cpp" | xargs rm -f
	rm -f ui/ui_*.h lang/xca_*.qm doc/*.html doc/xca.1.gz img/imgres.cpp
	rm -f lang/*.xml lang/.build-stamp misc/dn.txt misc/eku.txt
	rm -f commithash.h misc/oids.txt
	rm -f xca$(SUFFIX) setup_xca*.exe *.dmg xca-portable.zip
	rm -rf xca-$(VERSION)*

distclean: clean
	rm -f local.h Local.mak config.log config.status misc/Info.plist

dist: $(TARGET).tar.gz
$(TARGET).tar:
	test ! -z "$(TVERSION)"
	git archive --format=tar --prefix=$(TARGET)/ $(TAG) > _$@
	V=`tar xf _$@ -O $(TARGET)/VERSION` && \
		test "$(TVERSION)" = "$$V" && echo "$$V" > VERSION
	./bootstrap "$(TARGET)"
	tar -rf _$@ "$(TARGET)/configure"
	rm -rf "$(TARGET)"
	mv _$@ $@

$(TARGET).tar.gz: $(TARGET).tar
	gzip -9 < $^ > $@

snapshot:
	HASH=$$(git rev-parse HEAD) && \
	git archive --format=tar --prefix=xca-$${HASH}/ HEAD | \
		gzip -9 > xca-$${HASH}.tar.gz

install: xca$(SUFFIX) $(INSTTARGET)
	install -m 755 -d $(destdir)$(bindir)
	install -m 755 xca $(destdir)$(bindir)
	$(STRIP) $(destdir)$(bindir)/xca

xca-8859-1.nsi: misc/xca.nsi
	iconv -f utf8 -t iso-8859-15 -o "$@" "$<"

xca$(SUFFIX).signed: xca$(SUFFIX)

%.signed: %
	$(STRIP) $<
	if test -n "$(OSSLSIGN)"; then \
	  $(OSSLSIGN) $(OSSLSIGN_OPT) -in "$<" -out "$@"; \
	else \
	  mv "$<" "$@"; \
	fi

setup.exe: setup_xca-$(VERSION).exe
setup_xca-$(VERSION).exe: xca-8859-1.nsi xca-portable-$(VERSION)
	$(MAKENSIS) -DINSTALLDIR=xca-portable-$(VERSION) -DQTDIR=$(QTDIR) \
		-DVERSION=$(VERSION) -DBDIR=$(BDIR) -DTOPDIR=$(TOPDIR)\
		-NOCD -V2 -DEXTRA_VERSION=${EXTRA_VERSION} $<
	if test -n "$(OSSLSIGN)"; then \
	  $(OSSLSIGN) $(OSSLSIGN_OPT) -in $@ -out setup.tmp && mv setup.tmp $@; \
	fi

xca-portable-$(VERSION): xca$(SUFFIX).signed do.doc do.lang do.misc
	rm -rf $@
	mkdir -p $@/sqldrivers $@/platforms
	cp xca$(SUFFIX).signed $@/xca$(SUFFIX)
	cp $(patsubst %,misc/%.txt, dn eku oids) \
	   "$(TOPDIR)"/misc/*.xca doc/*.html lang/*.qm \
	   $(patsubst %,"$(QTDIR)/bin/%.dll", Qt5Gui Qt5Core Qt5Widgets \
		Qt5Sql libwinpthread-1 libstdc++-6 libgcc_s_dw2-1) \
	   "$(INSTALL_DIR)/bin/libltdl-7.dll" \
	   "$(INSTALL_DIR)/bin/libcrypto-1_1.dll" \
	   $(patsubst %,"$(QTDIR)/translations/qt_%.qm", de es pl pt ru fr sk) \
	   "$(TOPDIR)"/COPYRIGHT $@
	cp "$(QTDIR)/plugins/sqldrivers/qsqlite.dll" $@/sqldrivers
	cp "$(QTDIR)/plugins/platforms/qwindows.dll" $@/platforms

xca-portable.zip: xca-portable-$(VERSION).zip
xca-portable-$(VERSION).zip: xca-portable-$(VERSION)
	zip -r $@ $^

$(DMGSTAGE): xca$(SUFFIX)
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
	otool -l $(DMGSTAGE)/xca.app/Contents/MacOS/xca | grep -e "chris\|Users" >&2
	$(MACDEPLOYQT) $(DMGSTAGE)/xca.app
	rpath="`otool -l $(DMGSTAGE)/xca.app/Contents/MacOS/xca | grep -e "chris\|Users"`" && \
	if test -n "$$rpath"; then echo "  ERROR $$rpath"; false; fi
	-codesign --force --deep --signature-size=96000 -s "Christian Hohnstaedt" $(DMGSTAGE)/xca.app --timestamp

xca.dmg: $(MACTARGET).dmg

xca.app: $(DMGSTAGE)

$(MACTARGET).dmg: $(DMGSTAGE)
	hdiutil create -ov -fs HFS+ -volname "xca-$(VERSION)" -srcfolder "$<" "$@"

trans:
	$(MAKE) -C lang po2ts
	lupdate -locations relative $(TOPDIR)/xca.pro
	$(MAKE) -C lang xca.pot

.PHONY: $(SUBDIRS) $(INSTDIR) xca.app setup.exe doc lang macdeployqt/macdeployqt $(DMGSTAGE) commithash.h xca-portable.zip

do.doc do.lang headers: local.h

Local.mak: configure Local.mak.in
	$(TOPDIR)/configure

commithash.h:
	@$(PRINT) "  GEN    $@"
	$(TOPDIR)/gen_commithash.h.sh $@
