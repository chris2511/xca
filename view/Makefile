#
# $Id$
#
#########################################################################

NAMES=$(patsubst %.h, %, $(wildcard *.h))
OBJS=$(patsubst %,moc_%.o,$(NAMES)) $(patsubst %,%.o,$(NAMES))
DELFILES=$(patsubst %,moc_%.cpp,$(NAMES))

include ../Rules.mak

