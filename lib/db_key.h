#include "db_base.h"
#include "pki_key.h"
#include <qstringlist.h>

#ifndef DB_KEY_H
#define DB_KEY_H


class db_key: public db_base
{
    public:
	db_key(DbEnv *dbe, string DBfile, QListView *l);
	pki_base *newPKI();
	QStringList getPrivateDesc();
	bool updateView();
};

#endif
