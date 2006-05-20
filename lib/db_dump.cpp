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

	mydb.first();
	while (mydb.head_offset != OFF_EOF) {
		p = mydb.load(&h);
		free(p);
		printf("%3d: %c V%d O:%6d, L:%5d %s\n",
			i++, type[h.type], h.version, mydb.head_offset,
			h.len, h.name);
		mydb.next();
	}
}
