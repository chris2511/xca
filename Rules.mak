include ../Local.mak

all: target.obj

ifneq ($(prefix),)
  CFLAGS+= -DPREFIX=\"$(prefix)\"
endif
ifneq ($(basedir),)
  CFLAGS+= -DBASEDIR=\"$(basedir)\"
endif


# recompile all
re: clean all

# how to create a moc_* file
moc_%.cpp: %.h %.cpp
	$(MOC) $< -o $@

# how to create the headerfile from the *.ui
%.h: %.ui
	$(UIC) -o $@ $<

# same for the *.cpp file from the *.ui
%.cpp: %.h %.ui
	$(UIC) -o $@ -impl $^

# default compile rule
%.o: %.cpp 
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

# partial linking of objects in one directory
target.obj: $(OBJS)
	$(LD) -r -o $@ $(OBJS)

# delete the crap
clean:
	rm -f *~ *.o *.obj $(DELFILES)

distclean: clean

.SECONDARY:
