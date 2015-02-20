/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "exception.h"
#include "db_base.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <QFile>

#define RESIZE 1024
#define RDBUF 256

static int database = -1;

static int h2n(const char c)
{
	if (c>='0' && c<='9')
		return c-'0';
	if (c>='a' && c<='f')
		return c-'a'+10;
	if (c>='A' && c<='F')
		return c-'A'+10;
	return 0;
}

static char *read_data(const char *asc, int *retlen)
{
	char *p;
	int len=0, binlen=0, alloclen=RESIZE;
	p = (char*)malloc(alloclen);
	if (!p)
		return NULL;
	*retlen = 0;
	while(asc[len] != '\0') {
		p[binlen] = (h2n(asc[len])<<4) + h2n(asc[len+1]);
		len +=2;
		binlen++;
		if (binlen == alloclen) {
			alloclen +=RESIZE;
			p = (char *)realloc(p, alloclen);
		}
	}
	*retlen = binlen;
	return p;
}

QString readLine(QFile *file)
{
	QString data;
	qint64 begin;
	char buffer[RDBUF], *p;
	int ret, len;

	while ((ret = file->read(buffer, RDBUF-1)) >0) {
		p = strchr(buffer, '\n');
		if (p) {
			begin = file->pos() - ret;
			len = p - buffer;
			file->seek(begin + len + 1);
			//printf("Begin: %ld len=%d\n", begin,len);
			if (p > buffer && p[-1] == '\r')
				p--;
			*p = '\0';
			data += buffer;
			return data;
		}
		buffer[ret] = '\0';
		data += buffer;
		continue;
	}
	return data;
}

static int set_db(const char *name)
{
	QStringList sl;
	sl << "keydb" << "reqdb" << "certdb" << "tempdb" << "crldb" << "settings";
	for (int i=0; i<sl.count(); i++) {
		if (sl[i] == name)
			return i;
	}
	return -1;
}

static void handle_option(QString opt)
{
	QStringList sl = opt.split('=');
	if (sl.count() != 2) {
		printf("No '=' found in: '%s'\n", CCHAR(opt));
		return;
	}
	if (!sl[0].compare("database")) {
		database = set_db(CCHAR(sl[1]));
	}
}

int read_dump(const char *filename, db_base **dbs, char *md5, int md5_len)
{
	char *p;
	int ret = -1, retlen = 0;
	int kv=0;
	bool md5sum = false;
	pki_base *pki = NULL;
	db_base *db;
	QFile file;
	QString line;

	file.setFileName(filename);
	if (! file.open(QIODevice::ReadOnly)) {
		throw errorEx(filename, strerror(errno));
		return -1;
	}
	for (;;) {
		line = readLine(&file);
		//printf("Line: '%s'\n", CCHAR(line));
		if (line.isNull()) {
			ret = 0;
			break;
		}

		//printf("FIRST char = '%c'\n", CCHAR(line)[0]);
		if (line[0] == ' ') {
			if (database >= 0 && database < 5)
				db = dbs[database];
			else
				db = NULL;
			kv ^= 1;
			p = read_data(CCHAR(line.trimmed()), &retlen);
			if (db && !md5) {
				if (kv) {
					pki = db->newPKI();
					if (!pki) {
						break;
					}
					pki->setIntName(p);
				} else {
					try {
						pki->oldFromData((unsigned char*)p, retlen);
						db->insert(pki);
					} catch (errorEx &err) {
						printf("Error catched for '%s'\n", CCHAR(pki->getIntName()));
					}
				}
			} else if (md5) {
				if (database == 5) {
					p = read_data(CCHAR(line.trimmed()), &retlen);
					if (kv)
						md5sum = (!strcmp(p, "pwhash")) ? true : false;
					if (!kv && md5sum) {
						strncpy(md5, p, md5_len);
						ret = 0;
						break;
					}
				}
			}
			free(p);
		} else {
			if (kv) {
				printf("Binary value expected\n");
				break;
			}
			handle_option(line);
		}
	}
	file.close();
	if (ret <0) {
		throw errorEx(filename, strerror(errno));
		return -1;
	}
	return 0;
}
