include $(TOPDIR)/Local.mak

all: target.obj

ifneq ($(prefix),)
  CFLAGS+= -DPREFIX=\"$(prefix)\"
endif

ifneq ($(basedir),)
  CFLAGS+= -DBASEDIR=\"$(basedir)\"
endif

ifneq ($(etc),)
  CFLAGS+= -DETC=\"$(etc)\"
else
  CFLAGS+= -DETC=\"/etc/xca\"
endif

CFLAGS+= -DVER=\"$(VERSION)\"

SRCS=$(patsubst %.o, %.cpp, $(OBJS))
VERSION=$(shell cat $(TOPDIR)/VERSION )

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
%.o: %.cpp $(TOPDIR)/Local.mak
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

# partial linking of objects in one directory
target.obj: $(OBJS)
	$(LD) -r -o $@ $(OBJS)

# delete the crap
clean:
	rm -f *~ *.o *.obj $(DELFILES) .depend

distclean: clean
	rm -f -r .depend

.depend: $(SRCS)
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $(SRCS) > $@

.SECONDARY:
