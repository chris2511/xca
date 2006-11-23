/* vi: set sw=4 ts=4: */
#include "exception.h"
#include "db_base.h"
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#define RESIZE 1024

#if 0
#define throw
#define errorEx(a,b) printf("ERROR: %s : %s\n", (a), (b))

// db_base [5] = keys, reqs, certs temps, lists
typedef struct {
	char *data;
} db_base;
#endif

static int database = -1;

static int h2n(char c)
{
	if (c>='0' && c<='9')
		return c-'0';
	if (c>='a' && c<='f')
		return c-'a'+10;
	if (c>='A' && c<='F')
		return c-'A'+10;
	return 0;
}

static char *read_data(int fd, char *buf, int buflen, int *retlen)
{
	char *p;
	int len=0, binlen=0, alloclen=RESIZE;
	p = (char*)malloc(alloclen);
	if (!p)
		return NULL;
	buf[80] = '\0';
	*retlen = 0;
	//printf("Buffer(%d) = %p, '%s'\n", buflen, buf, buf);
	while(buf[len]!='\n') {
		while (len<buflen && buf[len]!='\n' && buf[len]) {
			p[binlen] = (h2n(buf[len])<<4) + h2n(buf[len+1]);
			//printf("len=%d, binlen=%d, char='%c'(%x) next is %p '%s'\n", len, binlen, p[binlen], p[binlen], buf+len, buf+len);
			len +=2;
			binlen++;
			if (binlen == alloclen) {
				alloclen +=RESIZE;
				p = (char *)realloc(p, alloclen);
			}
		}
		//printf("Reading again ???? \n");
		//printf("RR len=%d, buflen=%d, char='%c'\n", len, buflen, buf[len]);
		if (buf[len] == '\n')
			break;
		buflen = read(fd, buf, 80);
		len=0;
		if (buflen < 0) {
			if (p)
				free(p);
			close(fd);
			throw errorEx("read error", strerror(errno));
			return NULL;
		}
	}
	*retlen = binlen;
	return p;
}

static int set_db(const char *name)
{
	if (!strcmp(name, "keydb"))
		return 0;
	if (!strcmp(name, "reqdb"))
		return 1;
	if (!strcmp(name, "certdb"))
		return 2;
	if (!strcmp(name, "tempdb"))
		return 3;
	if (!strcmp(name, "crldb"))
		return 4;
	if (!strcmp(name, "settings"))
		return 5;
	return -1;
}

static void handle_option(char *buf, int len)
{
	char *p = strchr(buf, '=');
	if (!p) {
		printf("No = found: '%s'\n", buf);
		return;
	}
	*p = 0;
	if (!strcmp(buf, "database")) {
		printf("\nSwitching to database '%s'\n", p+1);
		database = set_db(p+1);
	}
}

int read_dump(const char *filename, db_base **dbs, char *md5)
{
	char buf[82];
	char *p;
	int fd, ret, retlen=0;
	off_t offs;
	int kv=0;
	pki_base *pki = NULL;
	db_base *db;

	database = -1;
	fd = open(filename, O_RDONLY);
	if (fd <0 ) {
		throw errorEx(filename, strerror(errno));
		return -1;
	}
	offs = 0;
	while ((ret = read(fd, buf, 81)) >0) {
		if (buf[0] == ' ') {
			if (database>=0 && database<5)
				db = dbs[database];
			else
				db = NULL;
			p = read_data(fd, buf+1, ret-1, &retlen);
			lseek(fd, offs +(2* (retlen+1)), SEEK_SET);
			kv ^=1;
			if (db && !md5) {
				if (kv) {
					printf("Importing: %s  ", p);
					pki = db->newPKI();
					if (!pki) {
						close(fd);
						return -1;
					}
					pki->setIntName(p);
				} else {
					printf("size=%d\n", retlen);
					try {
						pki->oldFromData((unsigned char*)p, retlen);
						db->insert(pki);
					} catch (errorEx &err) {
						printf("Error catched for '%s'\n", CCHAR(pki->getIntName()));
					}
				}
			} else if (md5) {
				if (database == 5) {
					static int md5sum=0;
					printf("Settings: '%s'\n", p);
					if (kv)
						md5sum = (!strcmp(p, "pwhash")) ? 1:0;
					if (!kv && md5sum) {
						printf("MD5SUM = '%s'\n", p);
						strncpy(md5, p, 50);
						close(fd);
						return 0;
					}
				}
			}
			free(p);
		} else {
			if (kv) {
				close(fd);
				printf("Binary value expected\n");
				return -1;
			}
			p = strchr(buf, '\n');
			if (!p) {
				close(fd);
				return -1;
			}
			*p=0;
			ret = lseek(fd, offs + (p-buf) +1 , SEEK_SET);
			//printf("SEEK to %d\n", ret);
			handle_option(buf, ret);
		}
		offs = lseek(fd, 0, SEEK_CUR);
	}
	if (ret <0) {
		close(fd);
		throw errorEx(filename, strerror(errno));
		return -1;
	}
	close(fd);
	return 0;
}
#if 0
int main(int argc, char *argv[])
{
	read_dump(argv[1], NULL);
}
#endif
