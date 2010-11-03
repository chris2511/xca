
ifeq ($(TOPDIR),)
TOPDIR=..
endif

PO_LANGUAGES=es tr
LANGUAGES=de ru $(PO_LANGUAGES)
QM_XCA=$(patsubst %, xca_%.qm, $(LANGUAGES))
QM_QT=$(patsubst %, qt_%.qm, $(LANGUAGES))
TS_XCA=$(patsubst %, xca_%.ts, $(PO_LANGUAGES))

%.qm: %.ts
	$(LRELEASE) $< -qm $@

all: $(QM_XCA)

install: $(QM_XCA)
	install -m 755 -d $(destdir)$(prefix)/share/xca
	install -m 644 $(QM_XCA) $(destdir)$(prefix)/share/xca

app:
	mkdir -p $(APPDIR)/Resources
	install -m 644 $(QM_XCA) $(APPDIR)/Resources
	(cd $(SYSROOT)/Developer/Applications/Qt/translations && \
		install $(QM_QT) $(APPDIR)/Resources )


po2ts: $(TS_XCA)
xca_%.ts: %.po
	po2ts -i $< | \
	  sed 's,^\( *<translation type="unfinished"\)>$$,\1/>,' |\
	  grep -v '^ *</translation>$$' > $@ || :
	#lconvert -i $< -of ts -o $@

xca.pot: xca.ts
	ts2po -P $< $@
	#lconvert -i $< -of po -o $@

clean:
	$(RM) $(QM_XCA)

include $(TOPDIR)/Local.mak
