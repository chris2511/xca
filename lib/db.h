#ifndef _XCA_DB_H_
#define _XCA_DB_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <qstring.h>
#include <qfile.h>

#define XCA_MAGIC 0xcadb1969
#define NAMELEN 80
#define FNAMLEN 256
#define OFF_EOF ((off_t)-1)

#define DBFLAG_DELETED  0x1
#define DBFLAG_OUTDATED 0x2

enum pki_type {
	none,
	asym_key,
	x509_req,
	x509,
	revokation,
	tmpl,
	setting,
};

typedef struct db_header_t {
	uint32_t magic;
	uint32_t len;		/* length of this entry */
	uint16_t headver;
	uint16_t type;
	uint16_t version;
	uint16_t flags;
	char name[NAMELEN];	/* name of the entry */
};

class db
{
    private:
	QFile file;
	QString name;
	QString errstr;
	int dberrno;
	db_header_t head;

	void init_header(db_header_t *db, int ver, int len, enum pki_type type,
		const char *name);
	bool verify_magic(void);
	void convert_header(db_header_t *h);
	void fileIOerr(QString s);

    public:
	off_t head_offset;
	db(QString, int mode = S_IRUSR | S_IWUSR);
	~db();
	bool eof();
	void first(int flag = DBFLAG_DELETED);
	int find(enum pki_type type, const char *name);
	int next(int flag = DBFLAG_DELETED);
	QString uniq_name(QString s, enum pki_type type);
	int rename(enum pki_type type, const char *name, const char *n);
	int add(const unsigned char *p, int len, int ver, enum pki_type type,
		const char *name);
	int set(const unsigned char *p, int len, int ver, enum pki_type type,
		const char *name);
	unsigned char *load(db_header_t *u_header);
	bool get_header(db_header_t *u_header);
	int erase(void);
	int shrink(int flags);

	static int intToData(unsigned char **p, uint32_t val);
	static uint32_t intFromData(const unsigned char **p);
	static int boolToData(unsigned char **p, bool val);
	static bool boolFromData(const unsigned char **p);
	static int stringToData(unsigned char **p, const QString val);
	static QString stringFromData(const unsigned char **p);
};

#endif

