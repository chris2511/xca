
ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif
include $(TOPDIR)/Rules.mak

PO_LANGUAGES=tr fr sk
LANGUAGES=de ru hr pl pt_BR es it zh_CN nl ja $(PO_LANGUAGES)
QM_XCA=$(patsubst %, xca_%.qm, $(LANGUAGES))
QM_QT=$(patsubst %, qt_%.qm, $(LANGUAGES))
TS_XCA=$(patsubst %, xca_%.ts, $(PO_LANGUAGES))

.install-stamp lang all: $(QM_XCA)

%.qm: %.ts
	@$(PRINT) "  LANG   [$(BASENAME)] $@"
	$(LRELEASE) -silent $< -qm $@

install: $(QM_XCA)
	install -m 755 -d $(DESTDIR)$(xca_prefix)
	install -m 644 $(QM_XCA) $(DESTDIR)$(xca_prefix)

app:
	mkdir -p $(APPDIR)/Resources
	install -m 644 $(QM_XCA) $(APPDIR)/Resources
	cd $(TRANSLATIONS) && \
	  for x in $(QM_QT); do \
	    test -f "$$x" && install $$x $(APPDIR)/Resources;\
	  done || :

po2ts: $(TS_XCA)
xca_%.ts: %.po
	$(LCONVERT) -if po -i $< -of ts -o $(@)

xca.pot: xca.ts
	$(LCONVERT) -if ts -of po -i $< -o $@

