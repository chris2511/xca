#include <qlistview.h>
#include <qpixmap.h>
#include <db_cxx.h>
#include "db_key.h"
#include "pki_x509.h"

#ifndef DB_X509_H
#define DB_X509_H


class db_x509: public db_base
{
    protected:
	db_key *keylist;
    public:
	db_x509(DbEnv *dbe, string DBfile, string DB, QListView *l, db_key *keyl);
	pki_base *newPKI();
	pki_x509 *findsigner(pki_x509 *client);
	bool updateView();
	void remFromCont(pki_base *pki);
};

#endif
