
ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif
include $(TOPDIR)/Rules.mak

PO_LANGUAGES=es tr fr
LANGUAGES=de ru hr $(PO_LANGUAGES)
QM_XCA=$(patsubst %, xca_%.qm, $(LANGUAGES))
QM_QT=$(patsubst %, qt_%.qm, $(LANGUAGES))
TS_XCA=$(patsubst %, xca_%.ts, $(PO_LANGUAGES))

lang all: $(QM_XCA)

%.qm: %.ts
	@$(PRINT) "  LANG   [$(BASENAME)] $@"
	$(LRELEASE) -silent $< -qm $@

install: $(QM_XCA)
	install -m 755 -d $(destdir)$(xca_prefix)
	install -m 644 $(QM_XCA) $(destdir)$(xca_prefix)

app:
	mkdir -p $(APPDIR)/Resources
	install -m 644 $(QM_XCA) $(APPDIR)/Resources
	cd $(TRANSLATIONS) && \
	  for x in $(QM_QT); do \
	    test -f "$$x" && install $$x $(APPDIR)/Resources;\
	  done || :

po2ts: $(TS_XCA)
xca_%.ts.xml: %.po
	po2ts -i $< > $(@)

xca_%.ts: indent.xslt xca_%.ts.xml
	xsltproc -o $@ $^

xca.pot: xca.ts
	ts2po -P $< $@

