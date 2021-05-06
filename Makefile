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
INSTSTAMP=$(patsubst %, %/.install-stamp, $(INSTDIR))
APPTARGET=$(patsubst %, app.%, $(INSTDIR))

DMGSTAGE=$(BUILD)/xca-$(VERSION)
MACTARGET=$(DMGSTAGE)${EXTRA_VERSION}
APPDIR=$(BUILD)/xca.app/Contents
OSSLSIGN=PKCS11SPY=/opt/SimpleSign/libcrypto3PKCS.so /usr/local/bin/osslsigncode

OSSLSIGN_OPT=sign -askpass -certs ~/osdch.crt -askpass \
	-key "pkcs11:object=Open%20Source%20Developer%2C%20Christian%20Hohnstaedt" \
	-pkcs11engine /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so \
	-pkcs11module /usr/lib/x86_64-linux-gnu/pkcs11-spy.so \
	-n "XCA $(VERSION)" -i https://hohnstaedt.de/xca \
	-t http://timestamp.comodoca.com -h sha2

ifeq ($(SUFFIX), .exe)
all: xca-portable.zip msi-installer-dir.zip
else
ifneq ($(MACDEPLOYQT),)
all: xca.dmg
ifneq ($(APPLE_DEVELOPER),)
APPLE_CERT_ID_APP=Developer ID Application: $(APPLE_DEVELOPER)
APPLE_CERT_3PARTY_INST=3rd Party Mac Developer Installer: $(APPLE_DEVELOPER)
APPLE_CERT_3PARTY_APP=3rd Party Mac Developer Application: $(APPLE_DEVELOPER)
all: xca.pkg
endif
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
export DOCTOOLFLAGS += -q
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
	$(MAKE) -C $* -f $(TOPDIR)/$*/Makefile VPATH=$(TOPDIR)/$* all

headers: do.ui commithash.h

%/.build-stamp: headers
	mkdir -p $*
	$(MAKE) -C $* -f $(TOPDIR)/$*/Makefile \
		VPATH=$(TOPDIR)/$*

%/.install-stamp: %/.build-stamp headers
	mkdir -p $*
	$(MAKE) -C $* -f $(TOPDIR)/$*/Makefile \
		VPATH=$(TOPDIR)/$* .install-stamp

$(INSTTARGET): install.%: %/.build-stamp
	mkdir -p $*
	$(MAKE) -C $* -f $(TOPDIR)/$*/Makefile \
		VPATH=$(TOPDIR)/$* install

$(APPTARGET): app.%: %/.install-stamp
	mkdir -p $*
	$(MAKE) -C $* -f $(TOPDIR)/$*/Makefile \
		VPATH=$(TOPDIR)/$* APPDIR=$(APPDIR) app

clean:
	find lib widgets img misc -name "*.o" \
				-o -name ".build-stamp" \
				-o -name ".depend" \
				-o -name "moc_*.cpp" | xargs rm -f
	rm -f ui/ui_*.h lang/xca_*.qm doc/*.html doc/xca.1.gz img/imgres.cpp
	rm -f lang/*.xml lang/.build-stamp misc/dn.txt misc/eku.txt
	rm -f commithash.h misc/oids.txt misc/variables.wxi doc/xca.1
	rm -f xca$(SUFFIX) *.dmg xca-portable*.zip msi-installer-dir*.zip xca*.msi
	rm -rf xca-$(VERSION)* msi-installer-dir-$(VERSION)* xca-portable-$(VERSION)* doc/html/ doc/qthelp/ doc/sphinx

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
	install -m 755 -d $(DESTDIR)$(bindir)
	install -m 755 xca $(DESTDIR)$(bindir)
	$(STRIP) $(DESTDIR)$(bindir)/xca

xca$(SUFFIX).signed: xca$(SUFFIX)

%.signed: %
	$(STRIP) $< || :
	if test -n "$(OSSLSIGN)"; then \
	  $(OSSLSIGN) $(OSSLSIGN_OPT) -in "$<" -out "$@" 2>/dev/null; \
	else \
	  mv "$<" "$@"; \
	fi

msi-installer-dir-$(VERSION): misc/xca.wxs misc/xca.bat misc/variables.wxi img/banner.bmp img/dialog.bmp img/xca.ico misc/copyright.rtf
	rm -f $@/* && mkdir -p $@ && cp -a $^ $@

xca-portable-$(VERSION): xca$(SUFFIX).signed do.doc do.lang do.misc
	rm -rf $@
	mkdir -p $@/sqldrivers $@/platforms $@/html $@/i18n $@/styles
	cp xca$(SUFFIX).signed $@/xca$(SUFFIX)
	cp $(patsubst %,misc/%.txt, dn eku oids) \
	   $(patsubst %,"$(QTDIR)/bin/%.dll", Qt5Gui Qt5Core Qt5Widgets \
		Qt5Sql Qt5Help libwinpthread-1 libstdc++-6 libgcc_s_seh-1) \
	   "$(INSTALL_DIR)/bin/libltdl-7.dll" \
	   "$(INSTALL_DIR)/bin/libcrypto-1_1-x64.dll" \
	   "$(TOPDIR)"/misc/*.xca "${TOPDIR}/../sql/"*.dll $@
	cp -a doc/qthelp/*.html doc/qthelp/xca.qhc doc/qthelp/xca.qch $@/html
	cp $(patsubst %,"$(QTDIR)/translations/qt_%.qm", de es pl pt ru fr sk it ja) \
		lang/*.qm $@/i18n
	sed 's/$$/\r/' < "$(TOPDIR)"/COPYRIGHT > $@/copyright.txt
	cp "$(QTDIR)/plugins/platforms/qwindows.dll" $@/platforms
	cp $(patsubst %,"$(QTDIR)/plugins/sqldrivers/%.dll", qsqlite qsqlmysql qsqlpsql qsqlodbc) $@/sqldrivers
	cp -a "$(QTDIR)/plugins/styles/qwindowsvistastyle.dll" "$@/styles"


xca-portable.zip: xca-portable-$(VERSION).zip
msi-installer-dir.zip: msi-installer-dir-$(VERSION).zip
%-$(VERSION).zip: %-$(VERSION)
	zip -r $@ $^

$(DMGSTAGE): xca.app
	@$(PRINT) "  DMGDIR $@"
	rm -rf $(DMGSTAGE)
	mkdir -p $(DMGSTAGE)
	cp -a xca.app $(DMGSTAGE)
	ln -s /Applications $(DMGSTAGE)
	install -m 644 $(TOPDIR)/COPYRIGHT $(DMGSTAGE)/COPYRIGHT.txt
	$(ENABLE_DOC)mkdir -p $(DMGSTAGE)/manual
	$(ENABLE_DOC)cp -a doc/html $(DMGSTAGE)/manual/
	$(ENABLE_DOC)ln -sf html/index.html $(DMGSTAGE)/manual/
	$(MACDEPLOYQT) $(DMGSTAGE)/xca.app
	touch $@

xca.app: xca$(SUFFIX) $(INSTSTAMP)
	@$(PRINT) "  APP    $@"
	rm -rf $@
	mkdir -p $@/Contents/MacOS
	install -m 755 $< $@/Contents/MacOS
	$(MAKE) $(APPTARGET)
	touch $@

xca.dmg: $(MACTARGET).dmg

CODESIGN=codesign --deep --signature-size=96000 --options=runtime --timestamp

$(MACTARGET).dmg: $(DMGSTAGE)
	@$(PRINT) "  DMG    $@"
	# Check for "Users" or "chris" in the resulting DMG image
	rpath="`cd $^ && otool -l xca.app/Contents/MacOS/xca | grep -e "chris\|Users" ||:`" && \
	if test -n "$$rpath"; then echo "  ERROR $$rpath"; false; fi
	test -z "$(APPLE_CERT_ID_APP)" || \
		$(CODESIGN) -s "$(APPLE_CERT_ID_APP)" $(DMGSTAGE)/xca.app
	hdiutil create -ov -fs HFS+ -volname "xca-$(VERSION)" -srcfolder "$<" "$@"

xca.pkg: $(MACTARGET).pkg

APPSTORE_DIR=AppStore
xca.app.dSYM: xca$(SUFFIX)
	@$(PRINT) "  SYM    $@"
	dsymutil $^ -o $@
	touch $@

$(MACTARGET).pkg: xca.app xca.app.dSYM
	@$(PRINT) "  PKG    $@"
	rm -rf $(APPSTORE_DIR)
	mkdir -p $(APPSTORE_DIR)/dSYM
	cp -a $^ $(APPSTORE_DIR)
	$(MACDEPLOYQT) $(APPSTORE_DIR)/xca.app -appstore-compliant
	$(CODESIGN) -s "$(APPLE_CERT_3PARTY_APP)" --entitlements $(TOPDIR)/misc/entitlement.plist $(APPSTORE_DIR)/xca.app
	# Having the xca.app.dSYM around is apparently not sufficient
	symbols -noTextInSOD -noDaemon -arch all \
		-symbolsPackageDir $(APPSTORE_DIR)/dSYM \
		xca.app.dSYM/Contents/Resources/DWARF/xca
	productbuild --symbolication $(APPSTORE_DIR)/dSYM \
		--component $(APPSTORE_DIR)/xca.app /Applications \
		--sign "$(APPLE_CERT_3PARTY_INST)" $@

trans:
	$(MAKE) -C lang po2ts
	lupdate -locations relative $(TOPDIR)/xca.pro
	$(MAKE) -C lang xca.pot

.PHONY: $(SUBDIRS) $(INSTDIR) commithash.h xca-portable.zip msi-installer-dir.zip

do.doc do.lang headers: local.h

Local.mak: configure Local.mak.in
	$(TOPDIR)/configure

commithash.h:
	@$(PRINT) "  GEN    $@"
	$(TOPDIR)/gen_commithash.h.sh $@
