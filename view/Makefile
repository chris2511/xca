#
# $Id$
#
#########################################################################

ifeq ($(TOPDIR),)
TOPDIR=..
endif

NAMES=CertView CrlView KeyView ReqView TempView XcaListView
OBJS=$(patsubst %, moc_%.o, $(NAMES)) $(patsubst %, %.o, $(NAMES))
DELFILES=$(patsubst %, moc_%.cpp, $(NAMES))

include $(TOPDIR)/Rules.mak

ifeq ($(DEP), yes)
  sinclude .depend
endif  
