ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

DELFILES=xca*.html xca.1.gz

doc: xca.1.gz html/index.html qthelp/xca.qhc
include $(TOPDIR)/Rules.mak

%.1.gz: %.1
	@$(PRINT) "  MAN    [$(BASENAME)] $@"
	gzip -9 <$^ >$@

xca.1: xca.1.head xca.1.options xca.1.tail
	cat $^ > $@

html/index.html: static/bigcert.png conf.py
	@$(PRINT) "  HTML   [$(BASENAME)] $@"
	$(DOCTOOL) $(DOCTOOLFLAGS) -b html -a -E -c . $(TOPDIR)/doc/rst html

qthelp/xca.qhcp: static/bigcert.png conf.py
	@$(PRINT) "  QTHELP [$(BASENAME)] $@"
	$(DOCTOOL) $(DOCTOOLFLAGS) -b qthelp -a -E -c . $(TOPDIR)/doc/rst qthelp

qthelp/xca.qhc: qthelp/xca.qhcp
	@$(PRINT) "  QTHGEN [$(BASENAME)] $@"
	$(HELPCOLL) $< -o $@

static/bigcert.png: ../img/bigcert.png
	mkdir -p static
	cp $^ $@

install: $(doc)
	$(ENABLE_DOC)install -m 755 -d $(DESTDIR)$(htmldir)
	$(ENABLE_DOC)install -m 644 qthelp/*.html qthelp/xca.q* $(DESTDIR)$(htmldir)
	install -m 755 -d $(DESTDIR)$(mandir)/man1
	install -m 644 *.1.gz $(DESTDIR)/$(mandir)/man1

app: xca.html
	mkdir -p $(APPDIR)/Resources
	install -m 644 xca*.html $(APPDIR)/Resources

database_schema.sql: ../widgets/database_schema.cpp
	sed 's/<<//; s/\\"/'"'"'/g; s,//,--,; s/"/ /g; s/\tschemas\[\(.*\)\].*/  -- Schema Version \1/; /^\t;$$/d' < $^ > $@

