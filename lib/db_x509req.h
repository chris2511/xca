#include <qstringlist.h>
#include "db_key.h"
#include "pki_x509req.h"

#ifndef DB_X509REQ_H
#define DB_X509REQ_H


class db_x509req: public db_base
{
	Q_OBJECT
    protected:
	db_key *keylist;
    public:
	db_x509req(DbEnv *dbe, string DBfile, QListView *l, db_key *keyl);
	pki_base *newPKI();
	QStringList getDesc();
	bool updateView();
    public slots:
	void delKey(pki_key *delkey);
    	void newKey(pki_key *newKey);
};

#endif
