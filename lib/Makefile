
ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

MOCNAMES=db_crl db_key db_temp db_x509 db_x509req db_x509super db_base db_token\
	pki_temp pki_x509 pki_crl pki_x509req pki_key pki_x509super pki_pkcs12 \
	pki_base pki_multi pki_evp pki_scard pass_info pki_pkcs7 database_model

NAMES=$(MOCNAMES) asn1int oid x509rev asn1time version \
	x509v3ext func load_obj x509name db settings \
	pk11_attribute pkcs11 pkcs11_lib Passwd builtin_curves entropy sql \
	dbhistory main arguments BioByteArray

OBJS=$(patsubst %, %.o, $(NAMES)) $(patsubst %, moc_%.o, $(MOCNAMES))

include $(TOPDIR)/Rules.mak
sinclude .depend
