#include <db_cxx.h>
#include "RSAkey.h"
#include <qlistbox.h>

#ifndef KEYDB_H
#define KEYDB_H


class KeyDB: public QObject
{
    	Q_OBJECT
	Db *data;
	DbEnv *dbenv;
	QListBox *listView;
	unsigned char mem[100];
    public:
	KeyDB(QString DBfile, QListBox *list, 
	      QObject *parent, const char *name = 0);
	~KeyDB();
	bool updateView();
	bool insertKey(RSAkey *key);
	bool deleteKey(RSAkey *key);
	bool updateKey(RSAkey *key, QString desc);
	RSAkey *getSelectedKey();
};

#endif
