/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *  http://www.openssl.org which includes cryptographic software
 *  written by Eric Young (eay@cryptsoft.com)"
 *
 *  http://www.sleepycat.com
 *
 *  http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */

/* here we have the possibility to add our own OIDS */

#include <openssl/objects.h>
#include <qstringlist.h>
#include <qmessagebox.h>
#include <qdir.h>
#include <stream.h>
#include "func.h"
#include "oid.h"

/* reads additional OIDs from a file: oid, sn, ln */
static void readOIDs(QString fname)
{
	char buff[128];
	char *pb;
	FILE *fp;
	int line = 0;
	QStringList sl;
	//fprintf(stderr, "FILE: %s\n", fname.latin1());
	fp = fopen(fname.latin1(), "r");
	if (fp == NULL) return;
	while (fgets(buff, 127, fp)) {
		line++;
		pb = buff;
		while (*pb==' ' || *pb=='\t' ) pb++;
		if (*pb == '#' || *pb=='\n' || *pb=='\0') continue;
		sl.clear();
		sl = sl.split(':', QString(pb));
		if (sl.count() != 3) {
			QMessageBox::warning(NULL, QString(XCA_TITLE),
				QString("Error reading config file: ") + fname + " Line: " + QString::number(line) );
			return;
		}
		else {
			OBJ_create((char *)sl[0].stripWhiteSpace().latin1(),
			   	(char *)sl[1].stripWhiteSpace().latin1(),
			   	(char *)sl[2].stripWhiteSpace().latin1());
		}
	}
	fclose(fp);
}

void initOIDs(QString baseDir)
{
	QString oids = (QChar)QDir::separator();
	oids += "oids.txt";
	QString dir = getPrefix();
	
	readOIDs(dir + oids);
#ifndef _WIN32_
	QString etc = ETC;
	readOIDs(etc + oids);
#endif
	readOIDs(baseDir + oids);
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
	//fprintf(stderr, "OID FILE: %s\n", fname.latin1());
	fp = fopen(fname.latin1(), "r");
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

