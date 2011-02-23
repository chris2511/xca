
all:

install:
	install -m 755 -d $(destdir)$(prefix)/share/xca/ \
		$(destdir)$(prefix)/share/applications \
		$(destdir)$(prefix)/share/mime/packages
	install -m 644 *.txt *.xca $(destdir)$(prefix)/share/xca
	install -m 644 xca.desktop $(destdir)$(prefix)/share/applications
	install -m 644 xca.xml $(destdir)$(prefix)/share/mime/packages
	if test -z "$(destdir)"; then \
	  update-mime-database $(prefix)/share/mime || :; \
	  update-desktop-database || :; \
	fi

app:
	mkdir -p $(APPDIR)/Resources
	install -m 644 Info.plist PkgInfo $(APPDIR)
	install -m 644 *.txt *.xca $(APPDIR)/Resources

include $(TOPDIR)/Local.mak
