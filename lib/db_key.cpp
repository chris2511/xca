#include "db_key.h"


db_key::db_key(DbEnv *dbe, string DBfile, string DB, QListView *l)
	:db_base(dbe, DBfile, DB, l)
{
	QString path = PREFIX;
	icon = new QPixmap(path + "/share/xca/key.png");
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

