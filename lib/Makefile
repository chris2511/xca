
ifeq ($(TOPDIR),)
TOPDIR=..
endif

MOCNAMES=db_crl db_key db_temp db_x509 db_x509req db_x509super pki_base db_base
NAMES=$(MOCNAMES) asn1int oid pki_pkcs7 x509rev asn1time \
	pki_temp x509v3ext pki_x509 func pki_crl pki_x509req \
	load_obj pki_key pki_x509super main pki_pkcs12 x509name db import \
	pki_multi pki_evp pki_scard pk11_attribute pkcs11


OBJS=$(patsubst %, %.o, $(NAMES)) $(patsubst %, moc_%.o, $(MOCNAMES))
DELFILES=$(patsubst %,moc_%.cpp,$(MOCNAMES)) db_dump

include $(TOPDIR)/Rules.mak

ifeq ($(DEP), yes)
  sinclude .depend
endif

db_dump: db_dump.cpp db.o db.h
	gcc $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) db_dump.cpp db.o $(LIBS) -g -o $@
