#include "db_x509req.h"


db_x509req::db_x509req(DbEnv *dbe, string DBfile, string DB, QListBox *l)
		:db_base(dbe, DBfile, DB, l)
{
	loadContainer();
	updateView();
}

pki_base *db_x509req::newPKI(){
	return new pki_x509req();
}

QStringList db_x509req::gethasPrivateDesc(db_base *keydb)
{
	unsigned char *p;
	Dbc *cursor;
	if (int x = data->cursor(NULL, &cursor, 0))
		data->err(x,"DB new Cursor");
	Dbt *k = new Dbt();
	Dbt *d = new Dbt();
	string desc;
	QStringList x;
	pki_key *key, *refkey;
	pki_x509req *req = (pki_x509req *)newPKI();
	//cerr << "before While loop\n";
	while (!cursor->get(k, d, DB_NEXT)) {
		//cerr << "in loop\n";
		desc = (char *)k->get_data();
		p = (unsigned char *)d->get_data();
		int size = d->get_size();
		req->fromData(p, size);
		key = req->getKey();
		if ((refkey = (pki_key *)keydb->findPKI(key))!= NULL) {
		   if (refkey->isPrivKey()){
			x.append(desc.data());	
			cerr << desc <<endl;
		   }
		   delete(refkey); 
		}
		delete(key);
	}
	delete(req);
	delete (k);
	delete (d);
	return x;
}
