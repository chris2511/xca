
ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

OBJS=imgres.o
ifeq ($(HOST),w32)
  OBJS += w32res.o
endif

include $(TOPDIR)/Rules.mak
sinclude .depend

install: xca-32x32.xpm
	install -D -m 644 $^ $(destdir)$(prefix)/share/pixmaps/xca-32x32.xpm

imgres.cpp: imgres.rcc
	@$(PRINT) "  RCC    [$(BASENAME)] $@"
	$(RCC) -o $@ $<

imgres.rcc: bigcert.png bigcrl.png bigcsr.png bigkey.png bigtemp.png crl.png halfkey.png invalidcertkey.png invalidcert.png key.png netscape.png reqkey.png req.png revoked.png spki.png template.png validcertkey.png validcert.png scard.png

w32res.o: w32res.rc key.ico xca.ico xdb.ico
	@$(PRINT) " WINDRES $@"
	$(WINDRES) $< $@

app: xca-mac-icon.icns
	mkdir -p $(APPDIR)/Resources
	install -m 644 $^ $(APPDIR)/Resources

w32res.cpp:
	touch $@
