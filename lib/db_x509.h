#include <db_cxx.h>
#include "db_base.h"
#include "pki_x509.h"

#ifndef DB_X509_H
#define DB_X509_H


class db_x509: public db_base
{
    public:
	db_x509(DbEnv *dbe, string DBfile, string DB, QListBox *l)
		:db_base(dbe, DBfile, DB, l){return;};
	pki_base *newPKI();
};

#endif
