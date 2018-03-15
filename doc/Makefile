ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

DELFILES=xca*.html xca.1.gz changelog.html database_schema.html

doc: xca.1.gz xca.html changelog.html database_schema.html
include $(TOPDIR)/Rules.mak

%.1.gz: %.1
	@$(PRINT) "  MAN    [$(BASENAME)] $@"
	gzip -9 <$^ >$@

xca.html: xca.sgml
	rm -f xca*.html
	echo 'The documentation for XCA can be viewed online at: <a href="http://hohnstaedt.de/documentation">http://hohnstaedt.de/documentation</a>.' > $@
	test ! -f xca-doc.tgz || tar zxf xca-doc.tgz
	@$(PRINT) "  DOC    [$(BASENAME)] $@"
	$(ENABLE_DOC)$(DOCTOOL) $< >/dev/null

install: $(doc)
	$(ENABLE_DOC)install -m 755 -d $(destdir)$(htmldir)
	$(ENABLE_DOC)install -m 644 xca*.html $(destdir)$(htmldir)
	install -m 755 -d $(destdir)$(mandir)/man1
	install -m 644 *.1.gz $(destdir)/$(mandir)/man1

app: xca.html
	mkdir -p $(APPDIR)/Resources
	install -m 644 xca*.html $(APPDIR)/Resources

changelog.html: $(TOPDIR)/changelog $(TOPDIR)/doc/html.header
	( cat $(TOPDIR)/doc/html.header; \
	  echo '</head><body><h2>Changelog</h2><div><ul>'; \
	  sed  's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; 2,$$ s/^xca.*-pre[0-9][0-9] .*/ <\/li><li class="prerelease">&/; s/^xca \([^ ]*\) *\(.*\)/<\/ul><\/div><div id="changelog_\1"><h3>xca \1 \2<\/h3><ul>/; s/\*/<\/li><li>/'; \
	  echo '</body></html>' \
	) < $< > $@

database_schema.html: ../widgets/database_schema.cpp
	$(TOPDIR)/doc/code2html -lcxx -ohtml $< $@

upload: database_schema.html changelog.html xca.html
	scp *.html hohnstaedt.de:xca-doc/
