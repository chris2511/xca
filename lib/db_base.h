#include <db_cxx.h>
#include <qlistview.h>
#include <qlist.h>
#include <qpixmap.h>
#include "pki_base.h"

#ifndef DB_BASE_H
#define DB_BASE_H


class db_base
{
		
    protected:
	Db *data;
	DbEnv *dbenv;
	QListView *listView;
	QList<pki_base> container;
	char *passwd;
	QPixmap *icon;
    public:
	db_base(DbEnv *dbe, string DBfile, string db, QListView *l);
	virtual ~db_base();
	virtual pki_base *newPKI(){
		cerr<<"VIRTUAL CALLED: newPKI\n"; return NULL;}
	virtual bool updateView();
	bool insertPKI(pki_base *pki);
	bool deletePKI(pki_base *pki);
	bool updatePKI(pki_base *pki, string desc);
	pki_base *getSelectedPKI(string desc);
	pki_base *getSelectedPKI();
	pki_base *findPKI(pki_base *refpki);
	virtual void loadContainer();
	virtual void remFromCont(pki_base *pki);
};

#endif
