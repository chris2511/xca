#include "KeyDB.h"
#include <stdio.h>


KeyDB::KeyDB(DbEnv *dbe, QString DBfile, QListBox *list, 
	QObject *parent , const char *name = 0)
	:QObject( parent, name)
{
	listView = list;
	dbenv = dbe;
	data = new Db(dbe, 0);
	cerr << "DB:" << DBfile <<"\n";//
	int x;
	if ( x = data->open(DBfile,"keydb",DB_BTREE, DB_CREATE,0600)) 
		data->err(x,"DB open");
	//cerr << "before Update\n";
	updateView();
	//cerr << "after Update\n";
}


KeyDB::~KeyDB()
{
	data->close(0);
//	dbenv->close(0);
}



bool KeyDB::updateView()
{
	listView->clear();
	Dbc *cursor;
	if (int x = data->cursor(NULL, &cursor, 0))
		data->err(x,"DB new Cursor");
	Dbt *key = new Dbt();
	Dbt *data = new Dbt();
	QString desc;
	//cerr << "before While loop\n";
	while (!cursor->get(key, data, DB_NEXT)) {
		//cerr << "in loop\n";
		desc = (char *)key->get_data();
		listView->insertItem(desc);
	}
}


bool KeyDB::insertKey(RSAkey *key) 
{
	QString desc = key->description();
	QString orig = desc;
	int size=0;
	unsigned char *p;
	p = key->getKey(&size);
	int cnt=0;
	int x = DB_KEYEXIST;
	while (x == DB_KEYEXIST) {
	   Dbt k((void *)desc.latin1(), desc.length()+1);
	   Dbt d((void *)p, size);
           cerr << "Size: " << d.get_size() << "\n";
	
	   if (x = data->put(NULL, &k, &d, DB_NOOVERWRITE)) {
		data->err(x,"DB Error put");
	   	desc = orig + "_" + QString::number(++cnt);
	   }
	}
	if (x != DB_KEYEXIST && x != 0) {
	   data->err(x,"DB Error put TINE");
	   //return false;
	}
	OPENSSL_free(p);
	updateView();
	key->setDescription(desc);
	return true;
}


bool KeyDB::deleteKey(RSAkey *key) 
{
	QString desc = key->description();
	Dbt k((void *)desc.latin1(), desc.length()+1);
	int x = data->del(NULL, &k, 0);
	updateView();
	if (x){
	   data->err(x,"DB Error del");
	   return false;
	}
	return true;
}

bool KeyDB::updateKey(RSAkey *key, QString desc) 
{
	if (deleteKey(key)){
	   key->setDescription(desc);
	   return insertKey(key);
	}
	return true;
}


RSAkey *KeyDB::getSelectedKey(QString desc)
{
	unsigned char *p;
	RSAkey *targetKey = NULL;
	Dbt k((void *)desc.latin1(), desc.length()+1);
	Dbt d((void *)p, 0);
	int x = data->get(NULL, &k, &d, 0);
	p = (unsigned char *)d.get_data();
	int size = d.get_size();
	if (x) data->err(x,"DB Error get");
	else targetKey = new RSAkey(p, size);
	targetKey->setDescription(desc);
	return targetKey;
}

RSAkey *KeyDB::getSelectedKey()
{
	QString desc = listView->currentText();
	return getSelectedKey(desc);
}
	
QStringList KeyDB::getPrivateDesc()
{
	unsigned char *p;
	Dbc *cursor;
	if (int x = data->cursor(NULL, &cursor, 0))
		data->err(x,"DB new Cursor");
	Dbt *k = new Dbt();
	Dbt *d = new Dbt();
	QString desc;
	QStringList x;
	RSAkey *key;
	//cerr << "before While loop\n";
	while (!cursor->get(k, d, DB_NEXT)) {
		//cerr << "in loop\n";
		desc = (char *)k->get_data();
		p = (unsigned char *)d->get_data();
		int size = d->get_size();
		key = new RSAkey(p, size);
		if (!key->onlyPubKey) {
			x.append(desc);	
			cerr << desc <<endl;
		}
		delete(key);
		
	}
	return x;
}
