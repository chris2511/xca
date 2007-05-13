/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db.h"

int main(int argc, char *argv[])
{
	if (argc<2)
		return 1;

	QString database = argv[1];

	db mydb(database);
	unsigned char *p;
	db_header_t h;
	int i=0;
	char type[] = "NKRCLTSXX";

	mydb.first(0);
	while (!mydb.eof()) {
		p = mydb.load(&h);
		free(p);
		printf("%3d: %c V%d O:%6d, F:%x L:%5d %s\n",
			i++, type[h.type], h.version, mydb.head_offset,
			h.flags, h.len, h.name);
		mydb.next(0);
	}
}
