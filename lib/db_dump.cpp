/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db.h"
#include "exception.h"
#include <stdlib.h>

const char *QString2filename(const QString &fname)
{
#ifdef WIN32
	return fname.toLocal8Bit();
#else
	return fname.toUtf8();
#endif
}

QString filename2QString(const char *fname)
{
#ifdef WIN32
	return QString::fromLocal8Bit(fname);
#else
	return QString::fromUtf8(fname);
#endif
}

static QByteArray fileNameEncoderFunc(const QString &fileName)
{
	return QByteArray(QString2filename(fileName));
}

static QString fileNAmeDecoderFunc(const QByteArray &localFileName)
{
	return filename2QString(localFileName.constData());
}


int main(int argc, char *argv[])
{
	if (argc < 2)
		return 1;

	QFile::setEncodingFunction(fileNameEncoderFunc);
	QFile::setDecodingFunction(fileNAmeDecoderFunc);

	QString database = filename2QString(argv[1]);

	db mydb(database);
	unsigned char *p;
	db_header_t h;
	int i=0;
	char type[] = "NKRCLTSUXX";

	try {
		mydb.first(0);
		while (!mydb.eof()) {
			p = mydb.load(&h);
			free(p);
			printf("%3d: %c V%d O:%6zd, F:%x L:%5d %s\n",
				i++, type[h.type], h.version, mydb.head_offset,
				h.flags, h.len, h.name);
			mydb.next(0);
		}
	} catch (errorEx &ex) {
		printf("Exception: '%s'\n", ex.getCString());
	}
}
