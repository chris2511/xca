#include "db_key.h"



pki_base *db_key::newPKI(){
	cerr << "New Key (PKI)" << endl;
	return new pki_key("");
}


QStringList db_key::getPrivateDesc()
{
	unsigned char *p;
	Dbc *cursor;
	if (int x = data->cursor(NULL, &cursor, 0))
		data->err(x,"DB new Cursor");
	Dbt *k = new Dbt();
	Dbt *d = new Dbt();
	string desc;
	QStringList x;
	pki_key *key = (pki_key *)newPKI();
	//cerr << "before While loop\n";
	while (!cursor->get(k, d, DB_NEXT)) {
		//cerr << "in loop\n";
		desc = (char *)k->get_data();
		p = (unsigned char *)d->get_data();
		int size = d->get_size();
		key->fromData(p, size);
		if (!key->isPubKey()) {
			x.append(desc.c_str());	
			cerr << desc <<endl;
		}
		
	}
	delete(key);
	delete (k);
	delete (d);
	return x;
}

bool db_key::updateView()
{
	listView->clear();
	cerr << "UPDATEVIEW" <<endl;
	KeyInfo info; 
	Dbc *cursor;
	if (int x = data->cursor(NULL, &cursor, 0))
		data->err(x,"DB new Cursor");
	Dbt *key = new Dbt();
	Dbt *data = new Dbt();
	QString  desc, num;
	QPixmap *map = new QPixmap("test.png");
	QPixmap *map1 = new QPixmap("test1.png");
	QPixmap *tarmap;
	while (!cursor->get(key, data, DB_NEXT)) {
		desc = (char *)key->get_data();
		memcpy(&info, data->get_data(), sizeof(info));
		//desc += " (" + num.setNum(info.size * 8) + ")";
		tarmap = map1;
		if (info.onlyPubKey) tarmap = map;
		listView->insertItem(*tarmap, desc);
	}
	return true;
}

