#include "db_key.h"


db_key::db_key(DbEnv *dbe, string DBfile, QListView *l)
	:db_base(dbe, DBfile, "keydb")
{
	listView = l;
	loadContainer();
	keyicon[0] = loadImg("key.png");
	keyicon[1] = loadImg("halfkey.png");
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

void db_key::remFromCont(pki_base *pki)
{
	db_base::remFromCont(pki);
	emit delKey((pki_key *)pki);
}

void db_key::inToCont(pki_base *pki) 
{
	db_base::inToCont(pki);
	emit newKey((pki_key *)pki);
}


void db_key::updateViewPKI(pki_base *pki)
{
        db_base::updateViewPKI(pki);
        if (! pki) return;
        int pixnum = 0;
        QListViewItem *current = (QListViewItem *)pki->getPointer();
        if (!current) return;
	if (((pki_key *)pki)->isPubKey()) pixnum += 1;	
	current->setPixmap(0, *keyicon[pixnum]);
}
