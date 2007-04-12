/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

/* here we have the possibility to add our own OIDS */

#include <openssl/objects.h>
#include <qstringlist.h>
#include <qmessagebox.h>
#include <qdir.h>
#include "func.h"
#include "oid.h"

/* reads additional OIDs from a file: oid, sn, ln */
static void readOIDs(QString fname)
{
	char buff[128];
	QString pb;
	FILE *fp;
	int line = 0;
	QStringList sl;

	fp = fopen(fname.toAscii(), "r");
	if (fp == NULL)
		return;

	while (fgets(buff, 127, fp)) {
		line++;
		pb = buff;
		pb = pb.trimmed();
		if (pb.startsWith('#') || pb.size() == 0) continue;
		sl.clear();
		sl = pb.split(':');
		if (sl.count() != 3) {
			QMessageBox::warning(NULL, QString(XCA_TITLE),
				QString("Error reading config file: ") + fname + " Line: " +
				QString::number(line) );
			fclose(fp);
			return;
		}
		else {
			OBJ_create(sl[0].trimmed().toAscii(),
				sl[1].trimmed().toAscii(),
				sl[2].trimmed().toAscii());
		}
	}
	fclose(fp);
}

void initOIDs()
{
	QString oids = QString(QDir::separator()) + "oids.txt";
	QString dir = getPrefix();

	readOIDs(dir + oids);
#ifndef WIN32
	readOIDs(QString(ETC) + oids);
	readOIDs(QDir::homePath() + QDir::separator() + ".xca" + oids);
#endif
}

/* reads a list of OIDs/SNs from a file and turns them into a QValueList
 * of integers, representing the NIDs. Usually to be used by NewX509 for
 * the list of ExtendedKeyUsage and Distinguished Name
 */

NIDlist readNIDlist(QString fname)
{
	char buff[128];
	const char *pb;
	char *pbe;
	FILE *fp;
	int line = 0, nid;
	NIDlist nl;
	nl.clear();
	fp = fopen(CCHAR(fname), "r");
	if (fp == NULL) return nl;
	while (fgets(buff, 127, fp)) {
		line++;
		pb = buff;
		while (*pb==' ' || *pb=='\t' ) pb++;
		if (*pb == '#' ) continue;
		pbe = buff + strlen(buff) -1;
		while (*pbe == ' ' || *pbe == '\t' || *pbe == '\r' || *pbe == '\n')
			*pbe-- = '\0';

		nid = OBJ_txt2nid((char *)pb);
		if (nid == NID_undef)
			QMessageBox::warning(NULL, QString(XCA_TITLE),
				QString("Unknown (flying:-) Object: ") + fname +
				" Line: " + QString::number(line) );
		else
			nl += nid;
	}
	fclose(fp);
	return nl;
}

