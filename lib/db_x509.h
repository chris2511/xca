#include <qlistview.h>
#include <qpixmap.h>
#include "db_key.h"
#include "pki_x509.h"

#ifndef DB_X509_H
#define DB_X509_H


class db_x509: public db_base
{
	Q_OBJECT
    protected:
	db_key *keylist;
	QPixmap *certicon[4];
    public:
	db_x509(DbEnv *dbe, string DBfile, QListView *l, db_key *keyl);
	pki_base *newPKI();
	pki_x509 *findSigner(pki_x509 *client);
	bool updateView();
	void updateViewAll();
	void updateViewPKI(pki_base *pki);
	void remFromCont(pki_base *pki);
	void preprocess();
	QStringList getPrivateDesc();
	pki_key * findKey(pki_x509 *cert);
    public slots:
	void delKey(pki_key *delkey);
    	void newKey(pki_key *newKey);
};

#endif
