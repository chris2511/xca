#
# $Id$
#
#########################################################################

NAMES=$(patsubst %.cpp, %, $(wildcard *.cpp))
MOCNAMES=$(shell grep -H 'Q_OBJECT' *.h |sed 's/.h:.*//')
OBJS=$(patsubst %, %.o, $(NAMES)) $(patsubst %, moc_%.o, $(MOCNAMES))
DELFILES=$(patsubst %,moc_%.cpp,$(MOCNAMES))

include ../Rules.mak
  
