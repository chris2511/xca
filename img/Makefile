
ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

OBJS=imgres.o
ifeq ($(HOST), WINDOWS)
  OBJS += w32res.o
endif

include $(TOPDIR)/Rules.mak
sinclude .depend

ICON_SIZES = 16x16 32x32 48x48 64x64
ICONS = $(patsubst %,%/apps/xca.png, $(ICON_SIZES))
ICONS_SRC = $(patsubst %,xca-icons.iconset/icon_%.png, $(ICON_SIZES))
PIXMAPS = xca-32x32.xpm
ICONDIR = $(datadir)/icons/hicolor

install: install-pixmaps $(ICONS) $(ICONS_SRC)
.install-stamp: $(PIXMAPS) $(ICONS_SRC)

install-pixmaps: $(PIXMAPS)
	install -d $(DESTDIR)$(datadir)/pixmaps/
	install -m 644 $^ $(DESTDIR)$(datadir)/pixmaps/

%/apps/xca.png: xca-icons.iconset/icon_%.png
	install -d $(DESTDIR)$(ICONDIR)/$*/apps $(DESTDIR)$(ICONDIR)/$*/mimetypes
	install -m 0644 $^ $(DESTDIR)$(ICONDIR)/$@
	ln -s ../apps/xca.png $(DESTDIR)$(ICONDIR)/$*/mimetypes/x-xca-database.png
	ln -s ../apps/xca.png $(DESTDIR)$(ICONDIR)/$*/mimetypes/x-xca-template.png

imgres.cpp: imgres.rcc
	@$(PRINT) "  RCC    [$(BASENAME)] $@"
	$(RCC) -o $@ $<

imgres.rcc: bigcert.png bigcrl.png bigcsr.png bigkey.png bigtemp.png crl.png halfkey.png invalidcertkey.png invalidcert.png key.png netscape.png reqkey.png req.png template.png validcertkey.png validcert.png scard.png

w32res.o: w32res.rc xca.ico
	@$(PRINT) " WINDRES $@"
	$(WINDRES) $< $@

xca-icons.icns: xca-icons.iconset
	iconutil --convert icns $^

app: xca-icons.icns
	mkdir -p $(APPDIR)/Resources
	install -m 644 $^ $(APPDIR)/Resources

w32res.cpp:
	touch $@
