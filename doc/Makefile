ifeq ($(TOPDIR),)
TOPDIR=..
endif

all: doc
mandir=man
doc: xca.1.gz xca.html

xca.1.gz:
	gzip -9 <xca.1 >$@

xca.html: xca.sgml
	linuxdoc -B html $< || true

install: xca.1.gz
	install -m 755 -d $(destdir)$(prefix)/share/xca \
		$(destdir)$(prefix)/$(mandir)/man1
	install -m 644 xca*.html $(destdir)$(prefix)/share/xca
	install xca.1.gz $(destdir)$(prefix)/$(mandir)/man1

include $(TOPDIR)/Local.mak

