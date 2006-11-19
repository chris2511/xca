
ifeq ($(TOPDIR),)
TOPDIR=..
endif

include $(TOPDIR)/Local.mak

OBJS=imgres.o
ifeq ($(HOST),w32)
  OBJS += w32res.o
endif

DELFILES=imgres.cpp
all: target.obj
	echo $(OBJS)

imgres.cpp: imgres.rcc
	$(RCC) -o $@ $<

w32res.o: w32res.rc
	$(WINDRES) $< $@

include $(TOPDIR)/Rules.mak
