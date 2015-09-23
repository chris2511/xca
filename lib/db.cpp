/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db.h"
#include "base.h"
#include "func.h"
#include "exception.h"
#include <QStringList>
#include <QDebug>
#include <QDateTime>
#ifdef WIN32
#include <windows.h>
#else
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#endif

#define XNUM(n) CCHAR(QString::number((n), 16))

db::db(QString filename, QFlags<QFile::Permission> perm)
{
	name = filename;
	file.setFileName(filename);
	bool newFile = !file.exists();

	if (!file.open(QIODevice::ReadWrite)) {
		fileIOerr("open");
	} else {
		first();
		if (newFile)
			file.setPermissions(perm);
	}
}

db::~db()
{
	file.close();
}

void db::fileIOerr(QString s)
{
	errstr = QString("DB ") + s + "() '" + file.fileName() + "'";
	dberrno = errno;
	throw errorEx(errstr, strerror(errno));
}

void db::init_header(db_header_t *db, int ver, int len, enum pki_type type,
		QString name)
{
	memset(db, 0, sizeof(db_header_t));
	db->magic = htonl(XCA_MAGIC);
	db->len = htonl(sizeof(db_header_t)+len);
	db->headver = htons(1);
	db->type = htons(type);
	db->version = htons(ver);
	db->flags = 0;
	strncpy(db->name, name.toUtf8(), NAMELEN);
	db->name[NAMELEN-1] = '\0';
}

void db::convert_header(db_header_t *h)
{
	h->magic   = ntohl(head.magic);
	h->len     = ntohl(head.len);
	h->headver = ntohs(head.headver);
	h->type    = ntohs(head.type);
	h->version = ntohs(head.version);
	h->flags   = ntohs(head.flags);
	memcpy(h->name, head.name, NAMELEN);
}

bool db::verify_magic(void)
{
	if (!eof())
		if (ntohl(head.magic) != XCA_MAGIC) {
			return false;
		}
	return true;
}

bool db::eof()
{
	return head_offset == file.size();
}

int db::find(enum pki_type type, QString name)
{
	while (!eof()) {
		if (ntohs(head.type) == type) {
			if (name.isEmpty()) { /* only compare type */
				return 0;
			} else if (QString::fromUtf8(head.name) == name) {
				return 0;
			}
		}
		if (!verify_magic()) {
			return -1;
		}
		next();
	}
	return 1;
}

void db::first(int flag)
{
	int ret;
	memset(&head, 0, sizeof(db_header_t) );
	head_offset = 0;
	file.seek(0);
	ret = file.read((char*)&head, sizeof(db_header_t) );
	if (ret < 0 )
		fileIOerr("read");
	if (ret==0) {
		head_offset = file.size();
		return;
	}
	if (!verify_magic())
		return;
	if (ntohs(head.flags) & flag)
		next(flag);
}

int db::next(int flag)
{
	qint64 ret;
	qint64 garbage = -1;
	int result = 1;

	if (eof())
		return 1;

	head_offset += ntohl(head.len);
	if (head_offset >= file.size()) {
		head_offset = file.size();
		return 1;
	}
	while (1) {
		file.seek(head_offset);
		ret = file.read((char*)&head, sizeof head);
		if (ret==0) {
			head_offset = file.size();
			break;
		}
		if (ret < 0) {
			fileIOerr("read");
			return -1;
		}
		if (ret != sizeof head) {
			qWarning("next(): Short read: 0x%s of 0x%s @ 0x%s",
				XNUM(ret), XNUM(sizeof head),
				XNUM(head_offset));
			if (garbage != -1) {
				ret += head_offset - garbage;
				head_offset = garbage;
			}
			qWarning("next(): Truncating 0x%s garbage bytes @ 0x%s",
				XNUM(ret), XNUM(head_offset));
			if (backup())
				file.resize(head_offset);
			head_offset = file.size();
			return -1;
		}
		qint64 hlen = ntohl(head.len);
		if (!verify_magic()) {
			if (garbage == -1)
				garbage = head_offset;
			head_offset += 1;
			continue;
		} else {
			if (garbage != -1) {
				qWarning("next(): 0x%s bytes garbage skipped at 0x%s",
					XNUM(head_offset - garbage),
					XNUM(garbage));
			}
			garbage = -1;
			if (file.size() < head_offset + hlen) {
				qWarning("next(): Short item (%s of %s) at 0x%s",
					XNUM(ntohl(head.len)),
					XNUM(file.size() - head_offset),
					XNUM(head_offset));
				garbage = head_offset;
				/* invalidate the header */
				qWarning("Invalidate short item @  0x%s\n",
					XNUM(head_offset));
				file.seek(head_offset);
				char inval = 0xcb; // 0xca +1
				file.write(&inval, 1);
				head_offset += 4;
				continue;
			}
		}
		if (!(ntohs(head.flags) & flag)) {
			result = 0;
			break;
		} else {
			head_offset += hlen;
		}
	}
	if (garbage != -1) {
		qWarning("next(): 0x%s bytes garbage skipped at 0x%s",
			XNUM(head_offset - garbage), XNUM(garbage));
	}
	return result;
}

void db::rename(enum pki_type type, QString name, QString n)
{
	qint64 ret;

	first();
	if (find(type, n) == 0) {
		throw errorEx(QObject::tr("DB: Rename: '%1' already in use").arg(n));
	}
	first();
	if (find(type, name) != 0) {
		throw errorEx(QObject::tr("DB: Entry to rename not found: %1").arg(name));
	}
	strncpy(head.name, n.toUtf8(), NAMELEN);
	head.name[NAMELEN-1] = '\0';
	file.seek(head_offset);
	ret = file.write((char*)&head, sizeof(head));
	if (ret < 0) {
		fileIOerr("write");
	}
	if (ret != sizeof head) {
		throw errorEx(QObject::tr("DB: Write error %1 - %2"
				).arg(ret).arg(sizeof(head)));
	}
}

QString db::uniq_name(QString s, QList<enum pki_type> types)
{
	int i;
	QString myname;
	QStringList sl;
	bool ok;

	s = s.left(NAMELEN-6);
	sl = s.split("_");
	sl.last().toUInt(&ok, 10);
	if (ok && (sl.count() > 1)) {
		sl.removeLast();
		s = sl.join("_");
	}
	for (i=1, myname = s; ; i++) {
		bool found = false;
		foreach (enum pki_type type, types) {
			first();
			if (find(type, myname) == 0) {
				myname = s + QString("_%1").arg(i);
				found = true;
				break;
			}
		}
		if (!found)
			break;
	}
	return myname;
}

int db::add(const unsigned char *p, int len, int ver, enum pki_type type,
		QString name)
{
	db_header_t head;

	init_header(&head, ver, len, type, name);
	file.seek(file.size());

	if (file.write((char*)&head, sizeof head) != sizeof head) {
		fileIOerr("write");
		return -1;
	}
	if (file.write((char*)p, len) != len) {
		fileIOerr("write");
		return -1;
	}
	return 0;
}

int db::set(const unsigned char *p, int len, int ver, enum pki_type type,
		                QString name)
{
	qint64 ret;

	first();
	ret = find(type, name);
	if (ret != 0) {
		return add(p, len, ver, type, name);
	} else {
		file.seek(head_offset);
		if (len != (int)(ntohl(head.len) - sizeof(db_header_t))) {
			int flags;
			flags = head.flags;
			head.flags |= htons(DBFLAG_DELETED | DBFLAG_OUTDATED);

			if (file.write((char*)&head, sizeof head) !=
					sizeof head)
			{
				fileIOerr("write");
				return -1;
			}
			if (add(p, len, ver, type, name) < 0) {
				file.seek(head_offset);
				head.flags = flags;
				ret = file.write((char*)&head, sizeof head);
				if (ret != sizeof head)
					fileIOerr("write");
			}
			return 0;
		}
		head.version = htons(ver);
		if (file.write((char*)&head, sizeof head) != sizeof head) {
			fileIOerr("write");
			return -1;
		}
		if (file.write((char*)p, len) != len) {
			fileIOerr("write");
			return -1;
		}
	}
	return 0;
}


unsigned char *db::load(db_header_t *u_header)
{
	uint32_t size;
	qint64 ret;
	unsigned char *data;

	if (eof())
		return NULL;
	size = ntohl(head.len) - sizeof(db_header_t);
	data = (unsigned char *)malloc(size);
	file.seek(head_offset + sizeof(db_header_t));
	ret = file.read((char*)data, size);
	if (ret == (qint64)size) {
		if (u_header)
			convert_header(u_header);
		return data;
	} else {
		free(data);
		if (ret < 0)
			fileIOerr("read");
		return NULL;
	}
}

bool db::get_header(db_header_t *u_header)
{
	if (eof())
		return false;
	convert_header(u_header);
	return true;
}

int db::erase(void)
{
	if (eof())
		return -1;

	head.flags |= htons(DBFLAG_DELETED);

	file.seek(head_offset);
	if (file.write((char*)&head, sizeof(db_header_t)) != sizeof(db_header_t)) {
		fileIOerr("write");
		return -1;
	}
	return 0;
}

int db::shrink(int flags)
{
	qint64 ret, garbage = -1;
	uint32_t offs;
	char buf[BUFSIZ];
	QFile new_file;
	int result = 0;

	new_file.setFileName(name + "{shrink}");
	if (!new_file.open(QIODevice::ReadWrite)) {
		fileIOerr("open");
		return 1;
	}
	file.reset();

	while ((ret = file.read((char*)&head, sizeof head)) > 0) {
		if (ret < (qint64)sizeof head) {
			qWarning("shrink(): Short read: 0x%s instead of 0x%s",
				XNUM(ret), XNUM(sizeof head));
			result = 1;
			break;
		}
		if (!verify_magic()) {
			file.seek(file.pos() - sizeof(head) +1);
			if (garbage == -1)
				garbage = file.pos() -1;
			result = 1;
			continue;
		}
		if (garbage != -1)
			qWarning("shrink(): 0x%s garbage found at %s",
				XNUM(file.pos() - sizeof head - garbage),
				XNUM(garbage));
		garbage = -1;
		head_offset = ntohl(head.len) - sizeof(head);
		if ((ntohs(head.flags) & flags)) {
			/* FF to the next entry */
			if (!file.seek(head_offset + file.pos())) {
				result = 1;
				break;
			}
			continue;
		}
		if (head_offset + file.pos() > file.size()) {
			file.seek(file.pos() - sizeof(head) +4);
			if (garbage == -1)
				garbage = file.pos() -4;
			continue;
		}

		ret = new_file.write((char*)&head, sizeof(head));
		if (ret != sizeof(head)) {
			result = 2;
			break;
		}
		offs = head_offset;
		while (offs) {
			ret = file.read((char*)buf, (offs > BUFSIZ) ? BUFSIZ : offs);
			if (ret <= 0) {
				result = 3;
				break;
			}
			if (new_file.write(buf, ret) != ret) {
				result = 4;
				break;
			}
			offs -= ret;
		}
		if (offs)
			break;

	}
	new_file.close();
	file.close();
	QString backup, orig;

	switch (result) {
	case 0:
		/* everything is fine */
		result = mv(new_file);
		break;
	case 1:
		/* Some repaireable errors in the database occured.
		 * Keep the original as backup */
		backup = backup_name();
		QFile::remove(backup);
		orig = file.fileName();
		if (file.rename(backup)) {
			new_file.rename(orig);
		} else {
			QFile::remove(new_file.fileName());
			result = 2;
		}
		break;
	case 2:
	case 3:
	case 4:
		QFile::remove(new_file.fileName());
		result = 2;
		break;
	}
	return result;
}

QString db::backup_name()
{
	return file.fileName() + "_backup_" +
		QDateTime::currentDateTime()
		.toString("yyyyMMdd_hhmmss") + ".xdb";
}

bool db::backup()
{
	QFile this_file, new_file;
	QString backup = backup_name();
	qint64 ret, wret;
	char buf[BUFSIZ];

	this_file.setFileName(file.fileName());
	if (!this_file.open(QIODevice::ReadOnly)) {
		return false;
	}
	new_file.setFileName(backup);
	if (!new_file.open(QIODevice::ReadWrite)) {
		this_file.close();
		return false;
	}
	while (1) {
		ret = this_file.read(buf, sizeof buf);
		if (ret <= 0)
			break;
		wret = new_file.write(buf, ret);
		if (wret != ret)
			break;
	}
	this_file.close();
	new_file.close();
	return ret == 0;
}

// Move "new_file" to this database
int db::mv(QFile &new_file)
{
#ifdef WIN32
	// here we try to reimplement the simple "mv" command on unix
	// atomic renaming fails on WIN32 platforms and
	// forces us to work with temporary files :-(
	QString tempn = name + "{mv_orig}";
	QFile::remove(tempn);
	if (file.rename(tempn)) {
		if (new_file.rename(name)) {
			QFile::remove(tempn);
		} else {
			QFile::rename(tempn, name);
			QFile::remove(new_file.fileName());
			printf("%s file.error(%d)\n", CCHAR(name), file.error());
			return 2;
		}
	} else {
		printf("%s file.error(%d)\n", CCHAR(tempn), file.error());
		return 2;
	}
	return 0;
#else
	// use the global rename() function and not the method of this class
	char *newfile = strdup(filename2bytearray(new_file.fileName()));
	check_oom(newfile);
	int ret = ::rename(newfile, QString2filename(name)) == -1;
	free(newfile);
	return ret == 0 ? 0 : 2;
#endif
}

QByteArray db::intToData(uint32_t val)
{
	uint32_t v = htonl(val);
	return QByteArray((char*)&v, sizeof(uint32_t));
}

uint32_t db::intFromData(QByteArray &ba)
{
	uint32_t ret;
	if ((unsigned)(ba.count()) < sizeof(uint32_t)) {
		throw errorEx(QObject::tr("Out of data"));
	}
	memcpy(&ret, ba.constData(), sizeof(uint32_t));
	ba = ba.mid(sizeof(uint32_t));
	return ntohl(ret);
}

QByteArray db::boolToData(bool val)
{
	char c = val ? 1 : 0;
	return QByteArray(&c, 1);
}

bool db::boolFromData(QByteArray &ba)
{
	unsigned char c;
	if (ba.count() < 1)
		throw errorEx(QObject::tr("Out of data"));

	c = ba.constData()[0];
	ba = ba.mid(1);
	return c ? true : false;
}

QByteArray db::stringToData(const QString val)
{
	QByteArray ba = val.toUtf8();
	int idx = ba.indexOf('\0');
	if (idx == -1)
		ba += '\0';
	else
		ba.truncate(idx +1);
	return ba;
}

QString db::stringFromData(QByteArray &ba)
{
	int idx = ba.indexOf('\0');

	if (idx == -1)
		throw errorEx(QObject::tr("Error finding endmarker of string"));

	QString ret = QString::fromUtf8(ba.constData(), idx);
	ba = ba.mid(idx+1);
	return ret;
}
