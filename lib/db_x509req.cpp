#include "db_x509req.h"


db_x509req::db_x509req(DbEnv *dbe, string DBfile, string DB, QListView *l, db_key *keyl)
		:db_base(dbe, DBfile, DB, l)
{
	QString path = PREFIX;
	icon = new QPixmap(path + "/share/xca/req.png");
	keylist = keyl;
	loadContainer();
	updateView();
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
	QString path = PREFIX;
	path += "/share/xca/";
	cerr << "PATH=" << path << endl;
	QPixmap *pm[2];
	pm[0] = new QPixmap(path + "req.png");
        pm[1] = new QPixmap(path + "reqkey.png");
	pki_x509req *pki;
	QListViewItem *current;
	cerr <<"myupdate requests"<<endl;
	if ( container.isEmpty() ) return false;
	int f=0;
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
