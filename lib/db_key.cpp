#include "db_key.h"


db_key::db_key(DbEnv *dbe, string DBfile, QListView *l)
	:db_base(dbe, DBfile, "keydb")
{
	listView = l;
	icon = loadImg("key.png");
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
		if (pki->isPrivKey()) {
			x.append(pki->getDescription().c_str());	
		}
	}
	return x;
}

