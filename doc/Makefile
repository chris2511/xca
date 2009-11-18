ifeq ($(TOPDIR),)
TOPDIR=..
endif

DELFILES=*.html xca.1.gz 
all: doc
mandir=man
doc: xca.1.gz xca.html

xca.1.gz: xca.1
	gzip -9 <$^ >$@

xca.html: xca.sgml
	echo '<h1>No documentation generated</h1>' > $@
	$(LINUXDOC) -B html $<

install: xca.1.gz xca.html
	install -m 755 -d $(destdir)$(prefix)/share/xca \
		$(destdir)$(prefix)/$(mandir)/man1
	install -m 644 xca*.html $(destdir)$(prefix)/share/xca
	install xca.1.gz $(destdir)$(prefix)/$(mandir)/man1

clean:
	$(RM) xca.1.gz xca*.html

app: xca.html
	mkdir -p $(APPDIR)/Resources
	install -m 644 xca*.html $(APPDIR)/Resources

include $(TOPDIR)/Local.mak

