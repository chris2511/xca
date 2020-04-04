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
	find lib widgets img misc -name "*.o" \
				-o -name ".build-stamp" \
				-o -name ".depend" \
				-o -name "moc_*.cpp" | xargs rm -f
	rm -f ui/ui_*.h lang/xca_*.qm doc/*.html doc/xca.1.gz img/imgres.cpp
	rm -f lang/*.xml lang/.build-stamp misc/dn.txt misc/eku.txt
	rm -f commithash.h misc/oids.txt misc/variables.wxi
	rm -f xca$(SUFFIX) *.dmg xca-portable*.zip msi-installer-dir*.zip xca*.msi
	rm -rf xca-$(VERSION)* msi-installer-dir-$(VERSION)* xca-portable-$(VERSION)*

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

msi-installer-dir-$(VERSION): misc/xca.wxs misc/xca.bat misc/variables.wxi img/banner.bmp img/dialog.bmp img/key.ico misc/copyright.rtf
	rm -f $@/* && mkdir -p $@ && cp -ra $^ $@

xca-portable-$(VERSION): xca$(SUFFIX).signed do.doc do.lang do.misc
	rm -rf $@
	mkdir -p $@/sqldrivers $@/platforms $@/html $@/i18n $@/styles
	cp xca$(SUFFIX).signed $@/xca$(SUFFIX)
	cp $(patsubst %,misc/%.txt, dn eku oids) \
	   $(patsubst %,"$(QTDIR)/bin/%.dll", Qt5Gui Qt5Core Qt5Widgets \
		Qt5Sql libwinpthread-1 libstdc++-6 libgcc_s_seh-1) \
	   "$(INSTALL_DIR)/bin/libltdl-7.dll" \
	   "$(INSTALL_DIR)/bin/libcrypto-1_1-x64.dll" \
	   "$(TOPDIR)"/misc/*.xca "${TOPDIR}/../sql/"*.dll $@
	cp doc/*.html $@/html
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
	$(MACDEPLOYQT) $(DMGSTAGE)/xca.app

xca.dmg: $(MACTARGET).dmg

xca.app: $(DMGSTAGE)

$(MACTARGET).dmg: $(DMGSTAGE)
	# Check for "Users" or "chris" in the resulting DMG image
	rpath="`cd $(DMGSTAGE) && otool -l xca.app/Contents/MacOS/xca | grep -e "chris\|Users" ||:`" && \
	if test -n "$$rpath"; then echo "  ERROR $$rpath"; false; fi
	-codesign --force --deep --signature-size=96000 -s "Christian Hohnstaedt" $(DMGSTAGE)/xca.app --timestamp
	hdiutil create -ov -fs HFS+ -volname "xca-$(VERSION)" -srcfolder "$<" "$@"

trans:
	$(MAKE) -C lang po2ts
	lupdate -locations relative $(TOPDIR)/xca.pro
	$(MAKE) -C lang xca.pot

.PHONY: $(SUBDIRS) $(INSTDIR) xca.app doc lang macdeployqt/macdeployqt $(DMGSTAGE) commithash.h xca-portable.zip msi-installer-dir.zip

do.doc do.lang headers: local.h

Local.mak: configure Local.mak.in
	$(TOPDIR)/configure

commithash.h:
	@$(PRINT) "  GEN    $@"
	$(TOPDIR)/gen_commithash.h.sh $@
