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
#include <QtCore/QStringList>
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
			throw errorEx(QString("database error '") +
				file.fileName() +"'",
				"at: " + QString::number(head_offset));
			return false;
		}
	return true;
}

bool db::eof()
{
	return (head_offset == OFF_EOF);
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
		head_offset = OFF_EOF;
		return;
	}
	if (!verify_magic())
		return;
	if (ntohs(head.flags) & flag)
		next(flag);
}

int db::next(int flag)
{
	int ret;

	if (eof())
		return 1;

	head_offset += ntohl(head.len);
	file.seek(head_offset);
	ret = file.read((char*)&head, sizeof(db_header_t) );
	if (ret==0) {
		//printf("Next: EOF at %lu\n", head_offset);
		head_offset = OFF_EOF;
		return 1;
	}
	if (ret < 0) {
		fileIOerr("read");
		return -1;
	}
	if (ret != sizeof(db_header_t)) {
		printf("Length broken: %d instead of %ld\n", ret,
				(long)sizeof(db_header_t) );
		//ftruncate(fd, head_offset);
		head_offset = OFF_EOF;
		return -1;
	}
	if (!verify_magic()){
		printf("Garbage found at %lu\n", (unsigned long)head_offset);
		head_offset+=4;
		return next(flag);
	}
	if (ntohs(head.flags) & flag)
		return next(flag);

	return 0;
}

void db::rename(enum pki_type type, QString name, QString n)
{
	int ret;

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
	if (ret != sizeof(head)) {
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
	db_header_t db;

	init_header(&db, ver, len, type, name);
	file.seek(file.size());

	if (file.write((char*)&db, sizeof(db)) != sizeof(db)) {
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
	int ret;

	first();
	ret = find(type, name);
	if (ret == 1) {
		return add(p, len, ver, type, name);
	}
	if (ret == 0) {
		//printf("offs = %x, len=%d, head.len=%d name = %s flags=%x\n",
		//		head_offset, len, ntohl(head.len), head.name,
		//		ntohs(head.flags));
		file.seek(head_offset);
		if (len != (int)(ntohl(head.len) - sizeof(db_header_t))) {
			//printf("## Found and len unequal %d, %d\n",
			//	len, ntohl(head.len) - sizeof(db_header_t));
			int flags;
			flags = head.flags;
			head.flags |= htons(DBFLAG_DELETED | DBFLAG_OUTDATED);

			if (file.write((char*)&head, sizeof(db_header_t)) !=
					sizeof(db_header_t))
			{
				fileIOerr("write");
				return -1;
			}
			if (add(p, len, ver, type, name) < 0) {
				file.seek(head_offset);
				head.flags = flags;
				ret = file.write((char*)&head, sizeof(db_header_t));
				if (ret != sizeof(db_header_t))
					fileIOerr("write");
			}
			return 0;
		}
		//printf("## Overwriting entry at %u\n", head_offset);
		head.version = htons(ver);
		if (file.write((char*)&head, sizeof(db_header_t)) !=
						sizeof(db_header_t)) {
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
	unsigned ret;
	unsigned char *data;

	if (eof())
		return NULL;
	size = ntohl(head.len) - sizeof(db_header_t);
	data = (unsigned char *)malloc(size);
	file.seek(head_offset + sizeof(db_header_t));
	ret = file.read((char*)data, size);
	if (ret == size) {
		if (u_header)
			convert_header(u_header);
		return data;
	} else {
		free(data);
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
	int ret;
	uint32_t offs;
	char buf[BUFSIZ];
	QFile new_file;

	new_file.setFileName(name + "{new}");
	if (!new_file.open(QIODevice::ReadWrite)) {
		fileIOerr("open");
		return 1;
	}
	file.reset();

	while ((ret = file.read((char*)&head, sizeof(head))) > 0) {
		if (!verify_magic())
			return 1;
		head_offset = ntohl(head.len) - sizeof(head);
		if ((ntohs(head.flags) & flags)) {
			//printf("Skip Entry\n");
			/* FF to the next entry */
			offs = file.seek(head_offset + file.pos());
			//printf("Seeking to %d\n", offs);
			if (head_offset == -1)
				break;
			continue;
		}
		ret = new_file.write((char*)&head, sizeof(head));
		if (ret != sizeof(head))
			break;
		offs = head_offset;
		while (offs) {
			ret = file.read((char*)buf, (offs > BUFSIZ) ? BUFSIZ : offs);
			if (ret<=0)
				break;
			if (new_file.write(buf, ret) != ret)
				break;
			offs -= ret;
		}
		if (offs)
			break;

	}
	new_file.close();
	if (ret) {
		unlink(QString2filename(new_file.fileName()));
		return 1;
	}
	file.close();
	return mv(new_file);
}

int db::mv(QFile &new_file)
{
#ifdef WIN32
	// here we try to reimplement the simple "mv" command on unix
	// atomic renaming fails on WIN32 platforms and
	// forces us to work with temporary files :-(
	QString tempn = name + "{orig}";
	QFile::remove(tempn);
	if (file.rename(tempn)) {
		if (new_file.rename(name)) {
			QFile::remove(tempn);
		} else {
			QFile::rename(tempn, name);
			QFile::remove(new_file.fileName());
			return 1;
		}
	}
	return 0;
#else
	// use the global rename() function and not the method of this class
	char *newfile = strdup(filename2bytearray(new_file.fileName()));
	check_oom(newfile);
	int ret = ::rename(newfile, QString2filename(name)) == -1;
	free(newfile);
	return ret;
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
