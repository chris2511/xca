#include "db_x509.h"


db_x509::db_x509(DbEnv *dbe, string DBfile, string DB, QListBox *l)
		:db_base(dbe, DBfile, DB, l)
{
	loadContainer();
	updateView();
}

pki_base *db_x509::newPKI(){
	return new pki_x509();
}

pki_x509 *db_x509::findsigner(pki_x509 *client)
{
	unsigned char *p;
	Dbc *cursor;
	if (int x = data->cursor(NULL, &cursor, 0))
		data->err(x,"DB new Cursor");
	Dbt *k = new Dbt();
	Dbt *d = new Dbt();
	string desc;
	pki_x509 *signer;
	while (!cursor->get(k, d, DB_NEXT)) {
		desc = (char *)k->get_data();
		p = (unsigned char *)d->get_data();
		int size = d->get_size();
		signer = (pki_x509 *)newPKI();
		signer->fromData(p, size);
		cerr << "verifying " << signer->getDescription().c_str() << endl;
		signer->setDescription(desc);
		if (client->verify(signer)) {
			delete (k);
			delete (d);
			return signer;
		}
		delete(signer);
		
	}
	delete (k);
	delete (d);
	return NULL;
}
/*
bool db_x509::updateView()
{
	listView->clear();
	Dbc *cursor;
	if (int x = data->cursor(NULL, &cursor, 0))
		data->err(x,"DB new Cursor");
	Dbt *key = new Dbt();
	Dbt *data = new Dbt();
	pki_x509 *client;
	QString  desc;
	while (!cursor->get(key, data, DB_NEXT)) {
		desc = (char *)key->get_data();
		p = (unsigned char *)d->get_data();
		int size = d->get_size();
		client = (pki_x509 *)newPKI();
		client->fromData(p, size);
		signer = findsigner(client);
		
		listView->insertItem(desc);
	}
	return true;
}
*/
