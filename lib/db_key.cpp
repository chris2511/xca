#include "db_key.h"


db_key::db_key(DbEnv *dbe, string DBfile, QListView *l)
	:db_base(dbe, DBfile, "keydb")
{
	listView = l;
	loadContainer();
	updateView();
}

pki_base *db_key::newPKI(){
	return new pki_key("");
}


bool db_key::updateView()
{
        listView->clear();
	QPixmap *pm[2];
	pm[0] = loadImg("key.png");
        pm[1] = loadImg("halfkey.png");
	pki_key *pki;
	QListViewItem *current;
	cerr <<"myupdate keys"<<endl;
	if ( container.isEmpty() ) return false;
	QListIterator<pki_base> it(container); 
	for ( ; it.current(); ++it ) {
		pki = (pki_key *)it.current();
		// create the listview item
		current = new QListViewItem(listView, pki->getDescription().c_str());	
		CERR<< "Adding as parent: "<<pki->getDescription().c_str()<<endl;
		int pixnum = 0;
		if (pki->isPubKey()) pixnum += 1;	
		current->setPixmap(0, *pm[pixnum]);
	}				
	return true;
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
	container.remove(pki);
	emit delKey((pki_key *)pki);
}

bool db_key::insertPKI(pki_base *pki) 
{
	db_base::insertPKI(pki);
	emit newKey((pki_key *)pki);
	return true;
}
