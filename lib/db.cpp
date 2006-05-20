#include "db.h"
#include "base.h"
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
	fd = open(CCHAR(filename), O_RDWR | O_CREAT, mode);
	if (fd<0) {
		errstr = QString("DB open() failed: ") + filename +" "+ 
				strerror(errno);
		dberrno = errno;
		perror(CCHAR(filename));

	} else {
		first();
	}
}

db::~db()
{
	if (fd>=0)
		close(fd);
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
	db->name[NAMELEN] = '\0';
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
			printf("database error at %lu\n", head_offset);
			return false;
		}
	return true;
}

int db::find(enum pki_type type, const char *name)
{
	//int len, ret=0;
	if (head_offset == OFF_EOF)
		return 1;

	do {
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

	} while (next() == 0);
	//printf("Returning 1\n");
	return 1;
}

void db::first(void)
{
	int ret;
	memset(&head, 0, sizeof(db_header_t) );
	head_offset = lseek(fd, 0, SEEK_SET );
	ret = read(fd, &head, sizeof(db_header_t) );
	if (ret<=0) {
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

	head_offset = lseek(fd, head_offset + ntohl(head.len), SEEK_SET );
	ret = read(fd, &head, sizeof(db_header_t) );
	if (ret==0) {
		//printf("Next: EOF at %lu\n", head_offset);
		head_offset = OFF_EOF;
		return 1;
	}
	if (ret < 0) {
		printf("read() failed: %s\n", strerror(errno));
		return -1;
	}
	if (ret != sizeof(db_header_t)) {
		printf("Length broken: %d instead of %d\n", ret,
				sizeof(db_header_t) );
		ftruncate(fd, head_offset);
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
	printf("Off = %lu\n", head_offset);
	strncpy(head.name, n, NAMELEN);
	head.name[NAMELEN] = '\0';
	lseek(fd, head_offset, SEEK_SET);
	ret = write(fd, &head, sizeof(head));
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
			printf("duplicate entry found at %lx\n", head_offset);
			myname = QString("%1_%2").arg(s).arg(i);
			printf("Trying '%s'\n", CCHAR(myname));
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
	lseek(fd, 0, SEEK_END);

	if (write(fd, &db, sizeof(db)) != sizeof(db)) {
		printf("write() failed\n");
		return -1;
	}
	if (write(fd, p, len) != len) {
		printf("write() failed\n");
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
		printf("offs = %x, len=%d, head.len=%d name = %s flags=%x\n",
				head_offset, len, ntohl(head.len), head.name,
				ntohs(head.flags));
		lseek(fd, head_offset, SEEK_SET);
		if (len != ntohl(head.len) - sizeof(db_header_t)) {
			//printf("## Found and len unequal %d, %d\n",
			//	len, ntohl(head.len) - sizeof(db_header_t));
			int flags;
			flags = head.flags;
			head.flags |= htons(DBFLAG_DELETED | DBFLAG_OUTDATED);

			if (write(fd, &head, sizeof(db_header_t)) !=
					sizeof(db_header_t))
			{
				printf("erasing of %s at failed\n", head.name);
				dberrno = errno;
				return -1;
			}
			if (add(p, len, ver, type, name) < 0) {
				lseek(fd, head_offset, SEEK_SET);
				head.flags = flags;
				write(fd, &head, sizeof(db_header_t));
			}
			return 0;
		}
		//printf("## Overwriting entry at %u\n", head_offset);
		head.version = htons(ver);
		if (write(fd, &head, sizeof(db_header_t)) !=
						sizeof(db_header_t)) {
			printf("write() failed\n");
			return -1;
		}
		if (write(fd, p, len) != len) {
			printf("write() failed\n");
			return -1;
		}
	}
	return 0;
}


unsigned char *db::load(db_header_t *u_header)
{
	uint32_t size;
	int ret;
	unsigned char *data;

	if (head_offset == OFF_EOF)
		return NULL;
	size = ntohl(head.len) - sizeof(db_header_t);
	data = (unsigned char *)malloc(size);
	lseek(fd, head_offset + sizeof(db_header_t), SEEK_SET);
	ret = read(fd, data, size);
	if ((unsigned)ret == size) {
		if (u_header)
			convert_header(u_header);
		return data;

	} else {
		printf("read of %u bytes failed: %d\n", size, ret);
		free(data);
		return NULL;
	}
}

int db::erase(void)
{
	if (head_offset == OFF_EOF)
		return -1;

	head.flags |= htons(DBFLAG_DELETED);

	lseek(fd, head_offset, SEEK_SET);
	if (write(fd, &head, sizeof(db_header_t)) != sizeof(db_header_t)) {
		printf("erasing of %s at %u failed\n", head.name, head_offset);
		dberrno = errno;
		return -1;
	}
	return 0;
}

int db::shrink(int flags)
{
	int fdn, ret, i=0;
	uint32_t offs;
	char buf[BUFSIZ];

	QString filename = name + "{new}";
	fdn = open(CCHAR(filename), O_RDWR | O_CREAT, 0644);
	if (fdn<0) {
		errstr = QString("open() failed: ") + filename +" "+ 
				strerror(errno);
		return 1;
	}
	lseek(fd, 0, SEEK_SET);

	while ((ret = read(fd, &head, sizeof(head))) > 0) {
		if (!verify_magic())
			return 1;
		head_offset = ntohl(head.len) - sizeof(head);
		if ((ntohs(head.flags) & flags)) {
			//printf("Skip Entry\n");
			/* FF to the next entry */
			offs = (int)lseek(fd, head_offset, SEEK_CUR);
			//printf("Seeking to %d\n", offs);
			if (head_offset == (uint32_t)-1)
				break;
			continue;
		}
		ret = write(fdn, &head, sizeof(head));
		if (ret<0)
			break;
		offs = head_offset;
		while (offs) {
			ret = read(fd, buf, (offs > BUFSIZ) ? BUFSIZ : offs);
			if (ret<=0)
				break;
			ret = write(fdn, buf, ret);
			if (ret<0)
				break;
			offs -= ret;
		}
		if (offs)
			break;

	}
	close(fdn);
	if (ret) {
		unlink(CCHAR(filename));
		return 1;
	}
	close(fd);
	fd=-1;
	// use the global rename()  function and not the method of this class
	::rename(CCHAR(filename), CCHAR(name));
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
