
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

ICONS = \
		xca-16x16.png \
		xca-32x32.png \
		xca-64x64.png
PIXMAPS = \
		  xca-32x32.xpm
ICON_NAME = xca
ICONDIR = $(datadir)/icons/hicolor

install: install-pixmaps install-icons

install-pixmaps: $(PIXMAPS)
	install -D -m 644 $^ $(DESTDIR)$(datadir)/pixmaps/$(ICON_NAME).xpm

install-icons: $(ICONS)
	for SZ in 16 32 64; do \
		if [ -f xca-$${SZ}x$${SZ}.png ]; then \
			install -D -m 0644 xca-$${SZ}x$${SZ}.png $(DESTDIR)$(ICONDIR)/$${SZ}x$${SZ}/apps/$(ICON_NAME).png ; \
		fi ; \
	done

imgres.cpp: imgres.rcc
	@$(PRINT) "  RCC    [$(BASENAME)] $@"
	$(RCC) -o $@ $<

imgres.rcc: bigcert.png bigcrl.png bigcsr.png bigkey.png bigtemp.png crl.png halfkey.png invalidcertkey.png invalidcert.png key.png netscape.png reqkey.png req.png template.png validcertkey.png validcert.png scard.png

w32res.o: w32res.rc key.ico xca.ico xdb.ico
	@$(PRINT) " WINDRES $@"
	$(WINDRES) $< $@

app: xca-mac-icon.icns
	mkdir -p $(APPDIR)/Resources
	install -m 644 $^ $(APPDIR)/Resources

w32res.cpp:
	touch $@
