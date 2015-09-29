
ifeq ($(TOPDIR),)
TOPDIR=..
BUILD=..
endif

MOC_NAMES=MainWindow KeyDetail clicklabel XcaTreeView NewX509 \
	validity v3ext distname CertDetail CertExtend PwDialog \
	ImportMulti CrlDetail ExportDialog hashBox Options NewKey kvView \
	NewCrl SearchPkcs11 RevocationList XcaProxyModel XcaHeaderView \
	KeyTreeView TempTreeView ReqTreeView X509SuperTreeView CertTreeView \
	OidResolver

NAMES=$(MOC_NAMES) NewX509_ext MW_menu MW_help MW_database
OBJS=$(patsubst %,moc_%.o,$(MOC_NAMES)) $(patsubst %,%.o,$(NAMES))

include $(TOPDIR)/Rules.mak
sinclude .depend
