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
	QPixmap *icon;
    public:
	db_base(DbEnv *dbe, string DBfile, string db);
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
	Dbc *getCursor();
	bool freeCursor(Dbc *cursor);
	void *getData(void* key, int length, int *dsize);
	void *getData(string key, int *dsize);
	string getString(string key);
	string getString(char *key);
	int getInt(string key);
	void putData(void *key, int keylen, void *dat, int datalen);
	void putString(string key, void *dat, int datalen);
	void putString(string key, string dat);
	void putString(char *key, string dat);
	void putInt(string key, int dat);
	QPixmap *loadImg(const char *name);
};

#endif
