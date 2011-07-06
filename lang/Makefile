
ifeq ($(TOPDIR),)
TOPDIR=..
endif
include $(TOPDIR)/Rules.mak

PO_LANGUAGES=es tr fr
LANGUAGES=de ru $(PO_LANGUAGES)
QM_XCA=$(patsubst %, xca_%.qm, $(LANGUAGES))
QM_QT=$(patsubst %, qt_%.qm, $(LANGUAGES))
TS_XCA=$(patsubst %, xca_%.ts, $(PO_LANGUAGES))

lang all: $(QM_XCA)

%.qm: %.ts
	$(LRELEASE) $< -qm $@

install: $(QM_XCA)
	install -m 755 -d $(destdir)$(prefix)/share/xca
	install -m 644 $(QM_XCA) $(destdir)$(prefix)/share/xca

app:
	mkdir -p $(APPDIR)/Resources
	install -m 644 $(QM_XCA) $(APPDIR)/Resources
	cd $(SYSROOT)/Developer/Applications/Qt/translations && \
	  for x in $(QM_QT); do \
	    test -f "$$x" && install $$x $(APPDIR)/Resources;\
	  done


po2ts: $(TS_XCA)
xca_%.ts: %.po
	po2ts -i $< > $(@) # | \
	#lconvert -i $< -of ts -o $@

xca.pot: xca.ts
	ts2po -P $< $@
	#lconvert -i $< -of po -o $@

