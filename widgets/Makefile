
ifeq ($(TOPDIR),)
TOPDIR=..
endif

MOC_NAMES=MainWindow KeyDetail clicklabel XcaTreeView ExportKey NewX509 \
	validity v3ext ReqDetail distname CertDetail CertExtend ExportCert \
	ImportMulti CrlDetail ExportDer hashBox Options ScardDetail NewKey

NAMES=$(MOC_NAMES) NewX509_ext MW_menu MW_help MW_database
NAMES=$(MOC_NAMES) NewX509_ext MW_help MW_database
OBJS=$(patsubst %,moc_%.o,$(MOC_NAMES)) $(patsubst %,%.o,$(NAMES))
DELFILES=$(patsubst %,moc_%.cpp,$(MOC_NAMES))

include $(TOPDIR)/Rules.mak

ifeq ($(DEP), yes)
  sinclude .depend
endif
