
all: 

install:
	install -m 755 -d $(destdir)$(prefix)/share/xca/ \
		$(destdir)$(prefix)/share/applications
	install -m 644 *.txt $(destdir)$(prefix)/share/xca
	install -m 644 xca.desktop $(destdir)$(prefix)/share/applications

include $(TOPDIR)/Local.mak
