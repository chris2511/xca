#include "db_x509req.h"


db_x509req::db_x509req(DbEnv *dbe, string DBfile, QListView *l, db_key *keyl)
		:db_base(dbe, DBfile, "reqdb")
{
	listView = l;
	keylist = keyl;
	loadContainer();
	updateView();
	connect(keyl, SIGNAL(delKey(pki_key *)), this, SLOT(delKey(pki_key *)));
	connect(keyl, SIGNAL(newKey(pki_key *)), this, SLOT(newKey(pki_key *)));
}

pki_base *db_x509req::newPKI(){
	return new pki_x509req();
}

QStringList db_x509req::getDesc()
{
	pki_x509req *pki;
	QStringList x;
        if ( container.isEmpty() ) return x;
        for ( pki = (pki_x509req *)container.first(); pki != 0; pki = (pki_x509req *)container.next() ) {
		x.append(pki->getDescription().c_str());	
	}
	return x;
}

bool db_x509req::updateView()
{
        listView->clear();
	QPixmap *pm[2];
	pm[0] = loadImg("req.png");
        pm[1] = loadImg("reqkey.png");
	pki_x509req *pki;
	QListViewItem *current;
	cerr <<"myupdate requests"<<endl;
	if ( container.isEmpty() ) return false;
	QListIterator<pki_base> it(container); 
	for ( ; it.current(); ++it ) {
		pki = (pki_x509req *)it.current();
		// create the listview item
		current = new QListViewItem(listView, pki->getDescription().c_str());	
		cerr<< "Adding as parent: "<<pki->getDescription().c_str()<<endl;
		int pixnum = 0;
		if (keylist->findPKI(pki->getKey())) pixnum += 1;	
		current->setPixmap(0, *pm[pixnum]);
	}				
	return true;
}


void db_x509req::delKey(pki_key *delkey)
{
	updateView();
}


void db_x509req::newKey(pki_key *newkey)
{
	updateView();
}

