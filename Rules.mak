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
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

.SECONDARY:
