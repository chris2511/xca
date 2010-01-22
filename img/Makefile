
ifeq ($(TOPDIR),)
TOPDIR=..
endif

include $(TOPDIR)/Local.mak

OBJS=imgres.o
ifeq ($(HOST),w32)
  OBJS += w32res.o
endif

DELFILES=imgres.cpp
all: target.obj
	echo $(OBJS)

install:
	install -D -m 644 xca-32x32.xpm $(destdir)$(prefix)/share/pixmaps/xca-32x32.xpm

imgres.cpp: imgres.rcc
	$(RCC) -o $@ $<

imgres.rcc: bigcert.png bigcrl.png bigcsr.png bigkey.png bigtemp.png crl.png halfkey.png invalidcertkey.png invalidcert.png key.png netscape.png reqkey.png req.png revoked.png spki.png template.png validcertkey.png validcert.png scard.png
w32res.o: w32res.rc key.ico xca.ico xdb.ico
	$(WINDRES) $< $@

include $(TOPDIR)/Rules.mak
