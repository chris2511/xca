
ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

MOCNAMES=db_crl db_key db_temp db_x509 db_x509req db_x509super db_base db_token\
	pki_temp pki_x509 pki_crl pki_x509req pki_key pki_x509super pki_pkcs12 \
	pki_base pki_multi pki_evp pki_scard pass_info pki_pkcs7
NAMES=$(MOCNAMES) asn1int oid x509rev asn1time \
	x509v3ext func load_obj main x509name db import \
	pk11_attribute pkcs11 pkcs11_lib Passwd


OBJS=$(patsubst %, %.o, $(NAMES)) $(patsubst %, moc_%.o, $(MOCNAMES))

include $(TOPDIR)/Rules.mak
sinclude .depend

db_dump: db_dump.cpp db.o db.h
	gcc $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) db_dump.cpp db.o $(LIBS) -g -o $@
