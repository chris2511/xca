ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

DELFILES=xca*.html xca.1.gz conf.py
RST_FILES=arguments common-actions object-ids smartcard \
	certificate-input database options step-by-step \
	certificates index privatekey template changelog \
	introduction requests commandline miscellaneous \
	revocationlist

SPHINX_FILES=$(patsubst %,sphinx/%.rst,$(RST_FILES))

.build-stamp doc: xca.1.gz html/index.html qthelp/xca.qhc
qthelpfiles=qthelp/*.html qthelp/xca.qhc qthelp/xca.qch
.install-stamp: doc

include $(TOPDIR)/Rules.mak

%.1.gz: %.1
	@$(PRINT) "  MAN    [$(BASENAME)] $@"
	gzip -9 <$^ >$@

xca.1: xca.1.head xca.1.options xca.1.tail
	cat $^ > $@

html/index.html: sphinx/conf.py
	@$(PRINT) "  HTML   [$(BASENAME)] $@"
	$(ENABLE_DOC)$(DOCTOOL) -b html $(DOCTOOLFLAGS) sphinx html
	mkdir -p html && touch $@

qthelp/xca.qhcp: sphinx/conf.py
	@$(PRINT) "  QTHELP [$(BASENAME)] $@"
	$(ENABLE_DOC)$(DOCTOOL) -b qthelp $(DOCTOOLFLAGS) sphinx qthelp
	mkdir -p qthelp && touch $@

qthelp/xca.qhc: qthelp/xca.qhcp
	@$(PRINT) "  QTHGEN [$(BASENAME)] $@"
	$(ENABLE_DOC)$(HELPCOLL) $< -o $@

install: $(doc)
	$(ENABLE_DOC)install -m 755 -d $(DESTDIR)$(htmldir)
	$(ENABLE_DOC)install -m 644 $(qthelpfiles) $(DESTDIR)$(htmldir)
	install -m 755 -d $(DESTDIR)$(mandir)/man1
	install -m 644 *.1.gz $(DESTDIR)/$(mandir)/man1

app: $(doc)
	mkdir -p $(APPDIR)/Resources
	$(ENABLE_DOC)install -m 644 $(qthelpfiles) $(APPDIR)/Resources

sphinx/conf.py: conf.py sphinx/database_schema.sql sphinx/changelog sphinx/COPYRIGHT sphinx/_static/bigcert.png $(SPHINX_FILES)
	mkdir -p sphinx
	cp $< $@
sphinx/database_schema.sql: ../widgets/database_schema.cpp
	mkdir -p sphinx
	sed 's/<<//; s/\\"/'"'"'/g; s,//,--,; s/"/ /g; s/^[[:space:]]\+schemas\[\(.*\)\].*/  -- Schema Version \1/; /^\t$$/d' < $^ > $@
sphinx/changelog: ../changelog
	mkdir -p sphinx
	cp $^ $@
sphinx/COPYRIGHT: ../COPYRIGHT
	@mkdir -p sphinx
	cp $^ $@
sphinx/_static/bigcert.png: ../img/bigcert.png
	@mkdir -p sphinx/_static
	cp $^ $@
sphinx/%.rst: rst/%.rst
	@mkdir -p sphinx
	cp $^ $@
