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
#include <QDebug>
#include <QDir>
#include "func.h"
#include "oid.h"

int first_additional_oid = 0;

QMap<QString,const char*> oid_name_clash;

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
		sl = pb.split(QRegExp("\\s*:\\s*"));
		if (sl.count() != 3) {
			XCA_WARN(QObject::tr("Error reading config file %1 at line %2")
				 .arg(fname).arg(line));
			fclose(fp);
			return;
		} else {
			bool differs = false;
			QByteArray in_use, oid, sn, ln;

			oid = sl[0].toLatin1();
			sn = sl[1].toLatin1();
			ln = sl[2].toLatin1();

			int nid = OBJ_txt2nid(oid.constData());
			if (nid != NID_undef) {
				if (sn != OBJ_nid2sn(nid)) {
					qWarning() << "OID: " << oid <<
						"SN differs: " << sn <<
						" " << OBJ_nid2sn(nid);
					oid_name_clash[sn] = OBJ_nid2sn(nid);
					differs = true;
				}
				if (ln != OBJ_nid2ln(nid)) {
					printf("%s LN differs: '%s' '%s'\n",
						oid.constData(), ln.constData(),
						OBJ_nid2ln(nid));
					qWarning() << "OID: " << oid <<
						"LN differs: " << ln <<
						" " << OBJ_nid2ln(nid);
					oid_name_clash[ln] = OBJ_nid2ln(nid);
					differs = true;
				}
			} else {
				if (OBJ_txt2nid(sn.constData()) != NID_undef)
					in_use = sn;
				if (OBJ_txt2nid(ln.constData()) != NID_undef)
					in_use = ln;
			}
			ign_openssl_error();
			if (differs) {
				XCA_WARN(QObject::tr("The Object '%1' from file %2 line %3 is already known as '%4:%5:%6' and should be removed.")
					.arg(sl.join(":")).arg(fname).arg(line)
					.arg(OBJ_obj2QString(OBJ_nid2obj(nid), 1))
					.arg(OBJ_nid2sn(nid)).arg(OBJ_nid2ln(nid))
				);
			} else if (!in_use.isEmpty()) {
				nid = OBJ_txt2nid(in_use.constData());
				XCA_WARN(QObject::tr("The identifier '%1' for OID %2 from file %3 line %4 is already used for a different OID as '%5:%6:%7' and should be changed to avoid conflicts.")
					.arg(in_use.constData())
					.arg(oid.constData())
					.arg(fname).arg(line)
					.arg(OBJ_obj2QString(OBJ_nid2obj(nid), 1))
					.arg(OBJ_nid2sn(nid)).arg(OBJ_nid2ln(nid))
				);
			} else {
				OBJ_create(oid.constData(), sn.constData(),
					ln.constData());
			}
		}
	}
	fclose(fp);
	ign_openssl_error();
}

void initOIDs()
{
	QString oids = QString(QDir::separator()) + "oids.txt";
	QString dir = getPrefix();

	first_additional_oid = OBJ_new_nid(0);
	readOIDs(dir + oids);
#if !defined(Q_OS_WIN32)
#if !defined(Q_OS_MAC)
	readOIDs(QString(ETC) + oids);
#endif
#endif
	readOIDs(getUserSettingsDir() + oids);
}

/* reads a list of OIDs/SNs from a file and turns them into a QValueList
 * of integers, representing the NIDs. Usually to be used by NewX509 for
 * the list of ExtendedKeyUsage and Distinguished Name
 */

NIDlist readNIDlist(QString fname)
{
	char buff[128];
	const char *pb, *userdefined;
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

		userdefined = oid_name_clash[QString(pb)];
		if (userdefined)
			pb = userdefined;
		nid = OBJ_txt2nid((char *)pb);
		if (nid == NID_undef)
			XCA_WARN(QObject::tr("Unknown object '%1' in file %2 line %3")
				.arg(pb).arg(fname).arg(line));
		else
			nl += nid;
	}
	fclose(fp);
	return nl;
}
