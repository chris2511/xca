include $(BUILD)/Local.mak
export VERSION=$(shell cat $(TOPDIR)/VERSION )

BASENAME=$(shell basename `pwd`)

CPPFLAGS += -I$(TOPDIR) -I$(BUILD) -I$(BUILD)/ui

all: .build-stamp

.build-stamp: $(OBJS)
	for i in $(patsubst %, $(shell pwd)/%, $(OBJS)); do echo $$i; done > $@
	@$(PRINT) "  DONE   [$(BASENAME)]"

SRCS=$(patsubst %.o, %.cpp, $(OBJS))
HEADERS=$(shell ls *.h 2>/dev/null)
GCH=$(patsubst %, %.gch, $(HEADERS))

# how to create a moc_* file
moc_%.cpp: %.h %.cpp
	@$(PRINT) "  MOC    [$(BASENAME)] $@"
	$(MOC) $< -o $@

# how to create the headerfile from the *.ui
ui_%.h: %.ui
	@$(PRINT) "  UIC    [$(BASENAME)] $@"
	$(UIC) -o $@ $<

# default compile rule
%.o: %.cpp
	@$(PRINT) "  CC     [$(BASENAME)] $@"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

.depend: $(SRCS)
	@$(PRINT) "  DEP    [$(BASENAME)]"
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $^ > $@

.SECONDARY:
.PHONY: .build-stamp
