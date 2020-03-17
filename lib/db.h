/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCA_DB_H
#define __XCA_DB_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <QString>
#include <QFile>

#define XCA_MAGIC 0xcadb1969
#define NAMELEN 80
#define FNAMLEN 256

#define DBFLAG_DELETED  0x1
#define DBFLAG_OUTDATED 0x2

enum pki_type {
	none,
	asym_key,
	x509_req,
	x509,
	revocation,
	tmpl,
	setting,
	smartCard,
};

typedef struct {
	uint32_t magic;
	uint32_t len;		/* length of this entry */
	uint16_t headver;
	uint16_t type;
	uint16_t version;
	uint16_t flags;
	char name[NAMELEN];	/* name of the entry */
} db_header_t ;

class db
{
    private:
	QFile file;
	QString name;
	QString errstr;
	int dberrno;
	db_header_t head;

	void convert_header(db_header_t *h);
	void fileIOerr(QString s);
	QString backup_name();
	bool backup();

    public:
	bool verify_magic(void);
	qint64 head_offset;
	db(const QString &, QFlags<QFile::Permission> perm =
				QFile::ReadOwner | QFile::WriteOwner);
	~db();
	bool eof();
	void first(int flag = DBFLAG_DELETED);
	int find(enum pki_type type, QString name);
	int next(int flag = DBFLAG_DELETED);
	unsigned char *load(db_header_t *u_header);
	bool get_header(db_header_t *u_header);

	static QByteArray intToData(uint32_t val);
	static uint32_t intFromData(QByteArray &ba);
	static QByteArray boolToData(bool val);
	static bool boolFromData(QByteArray &ba);
	static QByteArray stringToData(const QString val);
	static QString stringFromData(QByteArray &ba);
};
#endif
