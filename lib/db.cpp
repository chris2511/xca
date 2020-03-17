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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define XNUM(n) CCHAR(QString::number((n), 16))

db::db(const QString &filename, QFlags<QFile::Permission> perm)
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
		else if (!verify_magic()) {
			file.close();
			throw errorEx("Unknown database format", filename);
		}
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

void db::convert_header(db_header_t *h)
{
	h->magic   = xntohl(head.magic);
	h->len     = xntohl(head.len);
	h->headver = xntohs(head.headver);
	h->type    = xntohs(head.type);
	h->version = xntohs(head.version);
	h->flags   = xntohs(head.flags);
	memcpy(h->name, head.name, NAMELEN);
}

bool db::verify_magic(void)
{
	if (!eof())
		if (xntohl(head.magic) != XCA_MAGIC) {
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
		if (xntohs(head.type) == type) {
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
	if (xntohs(head.flags) & flag)
		next(flag);
}

int db::next(int flag)
{
	qint64 ret;
	qint64 garbage = -1;
	int result = 1;

	if (eof())
		return 1;

	head_offset += xntohl(head.len);
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
		qint64 hlen = xntohl(head.len);
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
					XNUM(xntohl(head.len)),
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
		if (!(xntohs(head.flags) & flag)) {
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

unsigned char *db::load(db_header_t *u_header)
{
	uint32_t size;
	qint64 ret;
	unsigned char *data;

	if (eof())
		return NULL;
	size = xntohl(head.len) - sizeof(db_header_t);
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

QByteArray db::intToData(uint32_t val)
{
	uint32_t v = xhtonl(val);
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
	return xntohl(ret);
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
