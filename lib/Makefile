#
# $Id$
#
#########################################################################

ifeq ($(TOPDIR),)
TOPDIR=..
endif

#MOCNAMES=db_crl db_key db_temp db_x509 db_x509req db_x509super pki_base
#NAMES=$(MOCNAMES) asn1int oid pki_pkcs7 x509rev asn1time pass_info \
#	pki_temp x509v3ext db_base pki_x509 func pki_crl pki_x509req \
#	load_obj pki_key pki_x509super main pki_pkcs12 x509name

MOCNAMES= pki_base db_base db_key db_x509super db_x509req db_x509 db_temp
NAMES=$(MOCNAMES) db asn1int oid asn1time pass_info \
	func load_obj pki_key pki_x509super \
	main x509name pki_x509req x509v3ext pki_x509 x509rev pki_pkcs12 \
	pki_pkcs7 pki_temp


OBJS=$(patsubst %, %.o, $(NAMES)) $(patsubst %, moc_%.o, $(MOCNAMES))
DELFILES=$(patsubst %,moc_%.cpp,$(MOCNAMES))

include $(TOPDIR)/Rules.mak

ifeq ($(DEP), yes)
  sinclude .depend
endif  
