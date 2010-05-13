#
# Makefile for XCA
#
#####################################################################

TAG=RELEASE.$(TVERSION)
TARGET=xca-$(TVERSION)

export VERSION=$(shell cat $(TOPDIR)/VERSION )
export TOPDIR=$(shell pwd)

sinclude Local.mak

SUBDIRS=lib widgets img
OBJECTS=$(patsubst %, %/target.obj, $(SUBDIRS))
INSTDIR=misc lang doc img
CLEANDIRS=lang doc ui img
HDRDIRS=lib widgets ui

bindir=bin

all: headers xca$(SUFFIX) doc lang
	@echo -e "\n\n\nOk, compilation was successfull. \nNow do as root: 'make install'\n"

xca.o: $(OBJECTS)
	$(LD) $(LDFLAGS) $(OBJECTS) -r -o $@ $(SLIBS)

xca$(SUFFIX): xca.o
	$(CC) $(LDFLAGS) $(CFLAGS) $< $(LIBS) -o $@

doc: 
	$(MAKE) -C doc
lang: 
	$(MAKE) -C lang

headers:
	$(MAKE) -C ui $@

pheaders: headers
	for d in $(HDRDIRS); do $(MAKE) -C $$d pheaders; done

%/target.obj: headers
	$(MAKE) DEP=yes -C $* target.obj

clean:
	for x in $(SUBDIRS) $(CLEANDIRS); do $(MAKE) -C $${x} clean; done
	rm -f *~ xca$(SUFFIX) xca.o setup_xca*.exe

distclean:
	for x in $(SUBDIRS) $(CLEANDIRS); do $(MAKE) -C $${x} distclean; done
	rm -f conftest conftest.log local.h Local.mak *~

dist:
	test ! -z "$(TVERSION)"
	git archive --format=tar --prefix=$(TARGET)/ $(TAG) | \
		gzip -9 > $(TARGET).tar.gz

snapshot:
	HASH=$$(git rev-parse HEAD) && \
	git archive --format=tar --prefix=xca-$${HASH}/ HEAD | \
		gzip -9 > xca-$${HASH}.tar.gz

install: xca$(SUFFIX)
	install -m 755 -d $(destdir)$(prefix)/$(bindir)
	install -m 755 xca $(destdir)$(prefix)/$(bindir)
	$(STRIP) $(destdir)$(prefix)/$(bindir)/xca
	for d in $(INSTDIR); do \
	  $(MAKE) -C $$d install; \
	done


setup.exe: xca$(SUFFIX) misc/xca.nsi doc lang
	$(MAKE) -C lang
	$(STRIP) xca$(SUFFIX)
	$(MAKENSIS) -DINSTALLDIR=$(INSTALL_DIR) -DQTDIR=$(QTDIR) \
		-DVERSION=$(VERSION) -DBDIR=$(BDIR) -NOCD -V2 misc/xca.nsi

.PHONY: $(SUBDIRS) $(INSTDIR) xca.app setup.exe doc lang

doc lang headers: local.h

Local.mak local.h: configure
	./configure

