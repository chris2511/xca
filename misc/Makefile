
SRCPATH=$(VPATH)/

all:

include $(TOPDIR)/Rules.mak

install:
	install -m 755 -d $(destdir)$(xca_prefix) \
		$(destdir)$(datarootdir)/applications \
		$(destdir)$(datarootdir)/mime/packages
	install -m 644 $(SRCPATH)*.txt $(SRCPATH)*.xca \
			$(destdir)$(xca_prefix)
	install -m 644 $(SRCPATH)xca.desktop $(destdir)$(datarootdir)/applications
	install -m 644 $(SRCPATH)xca.xml $(destdir)$(datarootdir)/mime/packages
	if test -z "$(destdir)"; then \
	  update-mime-database $(datarootdir)/mime || :; \
	  update-desktop-database || :; \
	fi

app:
	mkdir -p $(APPDIR)/Resources
	install -m 644 $(SRCPATH)Info.plist $(SRCPATH)PkgInfo $(APPDIR)
	install -m 644 $(SRCPATH)*.txt $(SRCPATH)*.xca $(APPDIR)/Resources

