#
# $Id$
#
#####################################################################

TAG=$(shell echo "V.$(TVERSION)" |sed "s/\./_/g" )
TARGET=xca-$(TVERSION)

SUBDIRS=ui lib widgets view
OBJECTS=$(patsubst %, %/t.obj, $(SUBDIRS))

all: headers xca
re: clean all

xca: $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o xca
	@echo -e "\n\n\nOk, compilation was successfull. \nNow do as root: 'make install'\n"

headers:
	$(MAKE) -C ui $@

%/t.obj: headers
	$(MAKE) -C $* t.obj

clean:
	for x in $(SUBDIRS); do \
		$(MAKE) -C $${x} clean; \
	done
	rm -f *~ xca 

distclean: clean	
	rm -f Local.mak

dist: 
	test ! -z "$(TVERSION)"
	rm -rf $(TARGET) 
	cvs export -r $(TAG) -d $(TARGET) xca && \
	(cd $(TARGET) &&  autoconf && \
	./mkxcapro.sh && lrelease xca.pro && \
	cat rpm/xca.spec |sed s/VERSION/$(TVERSION)/g >rpm/$(TARGET)-1.spec && \
	cat lib/base.h.in |sed s/VERSION/$(TVERSION)/g >lib/base.h && \
	cat misc/xca.nsi |sed s/VERSION/$(TVERSION)/g >misc/$(TARGET).nsi && \
	rm -rf misc/xca.nsi rpm/xca.spec autom4te.cache && \
	cd doc && linuxdoc -B html xca.sgml || echo "no linuxdoc found -> continuing"; ) && \
	tar zcf $(TARGET).tar.gz $(TARGET) 
	#rm -rf ../$(TARGET)
	
install: xca
	$(STRIP) xca
	install -m 755 -d $(destdir)$(prefix)/share/xca $(destdir)$(prefix)/bin \
			$(destdir)$(prefix)/share/applications \
			$(destdir)$(prefix)/share/pixmaps
	install -m 755 xca $(destdir)$(prefix)/bin
	install -m 644 img/*.png $(destdir)$(prefix)/share/xca
	install -m 644 img/key.xpm $(destdir)$(prefix)/share/pixmaps/xca.xpm
	install -m 644 misc/xca.desktop $(destdir)$(prefix)/share/applications
	install -m 644 lang/xca_??.qm $(destdir)$(prefix)/share/xca

.PHONY: $(SUBDIRS)

Local.mak: configure
	./configure

sinclude Local.mak
