all: doc

mandir=man

doc: xca.1.gz
xca.1.gz:
	linuxdoc -B html xca.sgml || true
	gzip -9 <xca.1 >$@

install: xca.1.gz
	install -m 755 -d $(destdir)$(prefix)/share/xca \
		$(destdir)$(prefix)/$(mandir)/man1
	install -m 644 xca*.html $(destdir)$(prefix)/share/xca
	install xca.1.gz $(destdir)$(prefix)/$(mandir)/man1

include $(TOPDIR)/Local.mak

