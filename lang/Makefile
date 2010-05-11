
ifeq ($(TOPDIR),)
TOPDIR=..
endif

QM_FILES=xca_de.qm xca_es.qm xca_ru.qm

%.qm: %.ts
	$(LRELEASE) $< -qm $@

all: $(QM_FILES)

install: $(QM_FILES)
	install -m 755 -d $(destdir)$(prefix)/share/xca
	install -m 644 $(QM_FILES) $(destdir)$(prefix)/share/xca

app:
	mkdir -p $(APPDIR)/Resources
	install -m 644 $(QM_FILES) $(APPDIR)/Resources

clean:
	$(RM) $(QM_FILES)

include $(TOPDIR)/Local.mak
