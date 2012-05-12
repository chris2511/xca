ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

DELFILES=xca*.html xca.1.gz

doc: xca.1.gz xca.html
include $(TOPDIR)/Rules.mak

mandir=man

xca.1.gz: xca.1
	gzip -9 <$^ >$@

xca.html: xca.sgml
	rm -f xca*.html
	echo 'The documentation for XCA can be viewed online at: <a href="http://xca.sourceforge.net/">http://xca.sourceforge.net/</a>.' > $@
	test ! -f xca-doc.tgz || tar zxf xca-doc.tgz
	@$(PRINT) "  DOC    [$(BASENAME)] $@"
	$(LINUXDOC) -B html $< >/dev/null

install: xca.1.gz xca.html
	install -m 755 -d $(destdir)$(docdir) \
		$(destdir)$(prefix)/$(mandir)/man1
	install -m 644 xca*.html $(destdir)$(docdir)
	install xca.1.gz $(destdir)$(prefix)/$(mandir)/man1

app: xca.html
	mkdir -p $(APPDIR)/Resources
	install -m 644 xca*.html $(APPDIR)/Resources


