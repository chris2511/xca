#
# $Id$
#
############################################################################

ifeq ($(TOPDIR),)
TOPDIR=..
endif

MOC_NAMES=CertDetail ExportKey KeyDetail distname CrlDetail ExportTinyCA \
	MainWindow ReqDetail validity ExportCert ImportMulti NewX509 \
	CertExtend clicklabel v3ext
	
NAMES=$(MOC_NAMES) NewX509_ext MW_menu MW_help MW_database
OBJS=$(patsubst %,moc_%.o,$(MOC_NAMES)) $(patsubst %,%.o,$(NAMES))
DELFILES=$(patsubst %,moc_%.cpp,$(MOC_NAMES))

include $(TOPDIR)/Rules.mak

ifeq ($(DEP), yes)
  sinclude .depend
endif  
