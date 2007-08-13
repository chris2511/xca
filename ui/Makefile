
ifeq ($(TOPDIR),)
TOPDIR=..
endif

UINAMES=$(patsubst %.ui, ui_%, $(wildcard *.ui))
UI_H=$(patsubst %, %.h, $(UINAMES))
DELFILES=$(UI_H)

include ../Rules.mak

headers: $(UI_H)
