
ifeq ($(TOPDIR),)
TOPDIR=..
endif

LANGUAGES=de es ru
QM_XCA=$(patsubst %, xca_%.qm, $(LANGUAGES))
QM_QT=$(patsubst %, qt_%.qm, $(LANGUAGES))

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

clean:
	$(RM) $(QM_XCA)

include $(TOPDIR)/Local.mak
