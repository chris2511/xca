
ifeq ($(TOPDIR),)
TOPDIR=..
endif

include $(TOPDIR)/Local.mak

OBJS=imgres.o
ifeq ($(HOST),w32)
  OBJS += w32res.o
endif

DELFILES=imgres.cpp

include $(TOPDIR)/Rules.mak

install: xca-32x32.xpm
	install -D -m 644 $^ $(destdir)$(prefix)/share/pixmaps/xca-32x32.xpm

imgres.cpp: imgres.rcc
	$(RCC) -o $@ $<

imgres.rcc: bigcert.png bigcrl.png bigcsr.png bigkey.png bigtemp.png crl.png halfkey.png invalidcertkey.png invalidcert.png key.png netscape.png reqkey.png req.png revoked.png spki.png template.png validcertkey.png validcert.png scard.png

w32res.o: w32res.rc key.ico xca.ico xdb.ico
	$(WINDRES) $< $@

app: xca-mac-icon.icns
	mkdir -p $(APPDIR)/Resources
	install -m 644 $^ $(APPDIR)/Resources

