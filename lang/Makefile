QM_FILES=xca_de.qm xca_es.qm

.SUFFIXES: .ts .qm

.ts.qm:
	lrelease $< -qm $@

all: $(QM_FILES)

install: $(QM_FILES)
	install -m 755 -d $(destdir)$(prefix)/share/xca
	install -m 644 $(QM_FILES) $(destdir)$(prefix)/share/xca

clean:
	$(RM) $(QM_FILES)

include $(TOPDIR)/Local.mak
