#
# $Id$
#
############################################################################

MOC_NAMES=$(patsubst %.h, %, $(wildcard *.h))
NAMES=$(MOC_NAMES) NewX509_ext
OBJS=$(patsubst %,moc_%.o,$(MOC_NAMES)) $(patsubst %,%.o,$(NAMES))
DELFILES=$(patsubst %,moc_%.cpp,$(MOC_NAMES))

include ../Rules.mak

