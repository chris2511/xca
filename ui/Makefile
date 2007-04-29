
ifeq ($(TOPDIR),)
TOPDIR=..
endif

UINAMES=$(patsubst %.ui, ui_%, $(wildcard *.ui))
#OBJS=$(patsubst %, moc_%.o, $(UINAMES)) $(patsubst %, %.o, $(UINAMES))

#MOC_CPP=$(patsubst %, moc_%.cpp, $(UINAMES))
#UI_CPP=$(patsubst %, %.cpp, $(UINAMES))
UI_H=$(patsubst %, %.h, $(UINAMES))

#DELFILES=$(MOC_CPP) $(UI_CPP) $(UI_H)
DELFILES=$(UI_H)

#EXTRA_CFLAGS+=-I../widgets -I../view

include ../Rules.mak

headers: $(UI_H)
