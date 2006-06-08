
ifeq ($(TOPDIR),)
TOPDIR=..
endif

MOCNAMES=db_crl db_key db_temp db_x509 db_x509req db_x509super pki_base db_base
NAMES=$(MOCNAMES) asn1int oid pki_pkcs7 x509rev asn1time pass_info \
	pki_temp x509v3ext pki_x509 func pki_crl pki_x509req \
	load_obj pki_key pki_x509super main pki_pkcs12 x509name db import


OBJS=$(patsubst %, %.o, $(NAMES)) $(patsubst %, moc_%.o, $(MOCNAMES))
DELFILES=$(patsubst %,moc_%.cpp,$(MOCNAMES))

include $(TOPDIR)/Rules.mak

ifeq ($(DEP), yes)
  sinclude .depend
endif

db_dump: db_dump.cpp db.o db.h
	gcc $(CPPFLAGS) $(CFLAGS) db_dump.cpp db.o -lQtCore -g -o $@
