
ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

MOCNAMES=db_crl db_key db_temp db_x509 db_x509req db_x509super db_base db_token\
	pki_temp pki_x509 pki_crl pki_x509req pki_key pki_x509super pki_pkcs12 \
	pki_base pki_multi pki_evp pki_scard pass_info pki_pkcs7 main
NAMES=$(MOCNAMES) asn1int oid x509rev asn1time \
	x509v3ext func load_obj x509name db import \
	pk11_attribute pkcs11 pkcs11_lib Passwd builtin_curves entropy


OBJS=$(patsubst %, %.o, $(NAMES)) $(patsubst %, moc_%.o, $(MOCNAMES))

include $(TOPDIR)/Rules.mak
sinclude .depend

xca_db_stat$(SUFFIX): xca_db_stat.o db.o db.h
	@$(PRINT) "  LINK   $@"
	$(CC) $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) $(CFLAGS_XCA_DB_STAT) xca_db_stat.o db.o $(LIBS) -g -o $@
