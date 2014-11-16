/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db.h"
#include "exception.h"
#include <stdlib.h>
#include <QtCore/QByteArray>

QByteArray filename2bytearray(const QString &fname)
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
	return filename2bytearray(fileName);
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
	const char *type[] = {
		"(none)", "Software Key", "Request", "Certificate",
		"Revocation", "Template", "Setting", "Token key"
	};

	try {
		mydb.first(0);
		printf("Index Type          Ver Offset Flags   Len  Name\n");
		while (!mydb.eof()) {
			p = mydb.load(&h);
			free(p);
			if (h.type > smartCard)
				h.type = 0;
			printf("%5d %-12s%5d%7zx%6x%6x  %s\n",
				i++, type[h.type], h.version,
				(size_t)mydb.head_offset,
				h.flags, h.len, h.name);
			if (mydb.next(0))
				break;
		}
	} catch (errorEx &ex) {
		printf("Exception: '%s'\n", ex.getCString());
	}
}
