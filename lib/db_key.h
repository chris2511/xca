#include "db_base.h"
#include "pki_key.h"
#include <qstringlist.h>

#ifndef DB_KEY_H
#define DB_KEY_H


class db_key: public db_base
{
	Q_OBJECT
    protected:
	QPixmap *keyicon[2];
    public:
	db_key(DbEnv *dbe, string DBfile, QListView *l);
	pki_base *newPKI();
	QStringList getPrivateDesc();
	void updateViewPKI(pki_base *pki);
	void inToCont(pki_base *pki);
	void remFromCont(pki_base *pki);
    signals:
	void delKey(pki_key *delkey);
	void newKey(pki_key *newkey);
};

#endif
