#include "db_key.h"


db_key::db_key(DbEnv *dbe, string DBfile, string DB, QListView *l, char *pass)
	:db_base(dbe, DBfile, DB, l)
{
	passwd = pass;
	loadContainer();
	updateView();
}

pki_base *db_key::newPKI(){
	return new pki_key("");
}


QStringList db_key::getPrivateDesc()
{
	pki_key *pki;
	QStringList x;
	for ( pki = (pki_key *)container.first(); pki != 0; pki = (pki_key *)container.next() )	{
		cerr << pki->getDescription().c_str();
		if (pki->isPrivKey()) {
			x.append(pki->getDescription().c_str());	
			cerr << "found " <<endl;
		}
	}
	return x;
}

