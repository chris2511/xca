sinclude $(TOPDIR)/Local.mak

all: .build-stamp

.build-stamp: $(OBJS)
	echo $(patsubst %, $(shell pwd)/%, $(OBJS)) > $@

SRCS=$(patsubst %.o, %.cpp, $(OBJS))
HEADERS=$(shell ls *.h 2>/dev/null)
GCH=$(patsubst %, %.gch, $(HEADERS))

# recompile all
re: clean all

# how to create a moc_* file
moc_%.cpp: %.h %.cpp
	$(MOC) $< -o $@

# how to create the headerfile from the *.ui
ui_%.h: %.ui
	$(UIC) -o $@ $<

# default compile rule
%.o: %.cpp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

.depend: $(SRCS)
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $^ > $@

.SECONDARY:
