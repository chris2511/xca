#include "db_key.h"



pki_base *db_key::newPKI(){
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

