ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

DELFILES=xca*.html xca.1.gz xca_db_stat.1.gz

doc: xca.1.gz xca_db_stat.1.gz xca.html
include $(TOPDIR)/Rules.mak

%.1.gz: %.1
	@$(PRINT) "  MAN    [$(BASENAME)] $@"
	gzip -9 <$^ >$@

xca.html: xca.sgml
	rm -f xca*.html
	echo 'The documentation for XCA can be viewed online at: <a href="http://xca.sourceforge.net/">http://xca.sourceforge.net/</a>.' > $@
	test ! -f xca-doc.tgz || tar zxf xca-doc.tgz
	@$(PRINT) "  DOC    [$(BASENAME)] $@"
	$(DOCTOOL) $< >/dev/null

install: $(doc)
	install -m 755 -d $(destdir)$(htmldir) \
		$(destdir)$(mandir)/man1
	install -m 644 xca*.html $(destdir)$(htmldir)
	install *.1.gz $(destdir)/$(mandir)/man1

app: xca.html
	mkdir -p $(APPDIR)/Resources
	install -m 644 xca*.html $(APPDIR)/Resources
