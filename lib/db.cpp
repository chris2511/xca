#include "db.h"
#include "base.h"
#include "exception.h"
#ifdef __WIN32__
#include <windows.h>
#else
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#endif

db::db(QString filename, int mode)
{
	name = filename;
	file.setFileName(filename);
	if (!file.open(QIODevice::ReadWrite)) {
		fileIOerr("open");
	} else {
		first();
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
		const char *name)
{
	memset(db, 0, sizeof(db_header_t));
	db->magic = htonl(XCA_MAGIC);
	db->len = htonl(sizeof(db_header_t)+len);
	db->headver = htons(1);
	db->type = htons(type);
	db->version = htons(ver);
	db->flags = 0;
	strncpy(db->name, name, NAMELEN);
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
	if (head_offset != OFF_EOF)
		if (ntohl(head.magic) != XCA_MAGIC) {
			throw errorEx(QString("database error '") +
				file.fileName() +"'",
				"at: " + QString::number(head_offset));
			return false;
		}
	return true;
}

int db::find(enum pki_type type, const char *name)
{
	//int len, ret=0;

	while (head_offset != OFF_EOF) {
		//printf("Comparing %s -> %s at %lu\n", head.name, name,
				//head_offset);
		if (ntohs(head.type) == type) {
			if (name == NULL) { /* only compare type */
				//printf("typematch: %d\n", type);
				return 0;
			} else if (!strncmp(head.name, name, NAMELEN)) {
				//printf("namematch: %s\n", name);
				return 0;
			}
		}
		if (!verify_magic()) {
			return -1;
		}
		next();
	}
	//printf("Returning 1\n");
	return 1;
}

void db::first(void)
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
	if (ntohs(head.flags) & DBFLAG_DELETED)
		next();
}

int db::next(void)
{
	int ret;

	if (head_offset == OFF_EOF)
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
		printf("Length broken: %d instead of %d\n", ret,
				sizeof(db_header_t) );
		//ftruncate(fd, head_offset);
		head_offset = OFF_EOF;
		return -1;
	}
	if (!verify_magic()){
		printf("Garbage found at %lu\n", head_offset);
		head_offset+=4;
		return next();
	}
	if (ntohs(head.flags) & DBFLAG_DELETED)
		return next();

	return 0;
}

int db::rename(enum pki_type type, const char *name, const char *n)
{
	int ret;

	first();
	if (find(type, n) == 0) {
		printf("New name: %s already in use\n", n);
		return -1;
	}
	first();
	if (find(type, name) != 0) {
		printf("Entry to rename not found: %s\n", name);
		return -1;
	}
	strncpy(head.name, n, NAMELEN);
	head.name[NAMELEN-1] = '\0';
	file.seek(head_offset);
	ret = file.write((char*)&head, sizeof(head));
	if (ret < 0) {
		fileIOerr("write");
	}
	if (ret != sizeof(head)) {
		printf("DB: Write error %d - %d\n", ret, sizeof(head));
		return -1;
	}
	return 0;
}

QString db::uniq_name(QString s, enum pki_type type)
{
	int i;
	QString myname = s;

	first();
	for (i=1;;i++) {
		if (find(type, CCHAR(myname)) == 0) {
			myname = QString("%1_%2").arg(s).arg(i);
		} else {
			break;
		}
	}
	return myname;
}

int db::add(const unsigned char *p, int len, int ver, enum pki_type type,
		const char *name)
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
		                const char *name)
{
	int ret;

	first();
	ret = find(type, name);
	if (ret == 1) {
		printf("## Name not found -> add\n");
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

	if (head_offset == OFF_EOF)
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

int db::erase(void)
{
	if (head_offset == OFF_EOF)
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
		unlink(CCHAR(new_file.fileName()));
		return 1;
	}
	file.close();
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
		}
	}
#else
	// use the global rename()  function and not the method of this class
	::rename(CCHAR(new_file.fileName()), CCHAR(name));
#endif
	return 0;
}

int db::intToData(unsigned char **p, uint32_t val)
{
	int s = sizeof(uint32_t);
	uint32_t v = htonl(val);
	memcpy(*p, &v, s);
	*p += s;
	return s;
}

uint32_t db::intFromData(const unsigned char **p)
{
	int s = sizeof(uint32_t);
	uint32_t ret;
	memcpy(&ret, *p, s);
	*p += s;
	return ntohl(ret);
}

int db::boolToData(unsigned char **p, bool val)
{
	unsigned char c = val ? 1 : 0;
	*(*p)++ = c;
	return 1;
}

bool db::boolFromData(const unsigned char **p)
{
	unsigned char c = *(*p)++;
	return c ? true : false;
}

int db::stringToData(unsigned char **p, const QString val)
{
	int s = (val.length() +1) * sizeof(char);
	memcpy(*p, val.toAscii(), s);
	*p += s;
	return s;
}

QString db::stringFromData(const unsigned char **p)
{
	QString ret="";
	while(**p) {
		ret +=(char)**p;
		*p += sizeof(char);
	}
	*p += sizeof(char);
	return ret;
}
