#include <db_cxx.h>
#include <qlistbox.h>
#include "pki_base.h"

#ifndef DB_BASE_H
#define DB_BASE_H


class db_base
{
    protected:
	Db *data;
	DbEnv *dbenv;
	QListBox *listView;
	unsigned char mem[100];
    public:
	db_base(DbEnv *dbe, string DBfile, string db, QListBox *l);
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
};

#endif
