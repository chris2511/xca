include $(TOPDIR)/Local.mak

all: target.obj

SRCS=$(patsubst %.o, %.cpp, $(OBJS))
HEADERS=$(shell ls *.h)
GCH=$(patsubst %, %.gch, $(HEADERS))

pheaders: $(GCH)

# recompile all
re: clean all

# how to create a moc_* file
moc_%.cpp: %.h %.cpp
	$(MOC) $< -o $@

# how to create the headerfile from the *.ui
ui_%.h: %.ui
	$(UIC) -o $@ $<

# default compile rule
#%.o: %.cpp $(TOPDIR)/Local.mak
%.o: %.cpp
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

# partial linking of objects in one directory
target.obj: $(OBJS)
	$(LD) -r -o $@ $(OBJS)

# precompiled header
%.h.gch: %.h
	$(CC) $(CPPFLAGS) -xc++ -c $< -o $@

# delete the crap
clean:
	rm -f *~ *.o *.obj $(DELFILES)

distclean: clean
	rm -f -r .depend *.h.gch

.depend: $(SRCS)
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $(SRCS) > $@

.SECONDARY:
