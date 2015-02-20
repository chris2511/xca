/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

/* here we have the possibility to add our own OIDS */

#include <openssl/objects.h>
#include <QStringList>
#include <QMessageBox>
#include <QTextEdit>
#include <QDir>
#include "func.h"
#include "oid.h"

int first_additional_oid = 0;

/* reads additional OIDs from a file: oid, sn, ln */
static void readOIDs(QString fname)
{
	char buff[128];
	QString pb;
	FILE *fp;
	int line = 0;
	QStringList sl;

	fp = fopen_read(fname);
	if (fp == NULL)
		return;

	while (fgets(buff, 127, fp)) {
		line++;
		pb = buff;
		pb = pb.trimmed();
		if (pb.startsWith('#') || pb.size() == 0)
			continue;
		sl.clear();
		sl = pb.split(':');
		if (sl.count() != 3) {
			XCA_WARN(QString("Error reading config file: ") + fname + " Line: " +
				QString::number(line));
			fclose(fp);
			return;
		} else {
			QByteArray oid = sl[0].trimmed().toLatin1();
			QByteArray sn = sl[1].trimmed().toLatin1();
			QByteArray ln = sl[2].trimmed().toLatin1();

			int nid = OBJ_txt2nid(oid.constData());
			if ((nid != NID_undef) && (sn != OBJ_nid2sn(nid))) {
				printf("OID: '%s' SN differs: '%s' '%s'\n",
					oid.constData(), sn.constData(),
					OBJ_nid2sn(nid));
			}
			if ((nid == NID_undef) || (sn != OBJ_nid2sn(nid))) {
				OBJ_create(oid.constData(), sn.constData(),
					ln.constData());
			}
		}
	}
	fclose(fp);
}

void initOIDs()
{
	QString oids = QString(QDir::separator()) + "oids.txt";
	QString dir = getPrefix();

	first_additional_oid = OBJ_new_nid(0);
	readOIDs(dir + oids);
#ifndef WIN32
#if !defined(Q_WS_MAC)
	readOIDs(QString(ETC) + oids);
#endif
	readOIDs(getUserSettingsDir() + oids);
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
	fp = fopen_read(fname);
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
			XCA_WARN(QString("Unknown (flying:-) Object: ") + fname +
				" Line: " + QString::number(line));
		else
			nl += nid;
	}
	fclose(fp);
	return nl;
}
