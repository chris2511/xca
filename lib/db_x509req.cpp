#include "db_x509req.h"


db_x509req::db_x509req(DbEnv *dbe, string DBfile, QListView *l, db_key *keyl)
		:db_base(dbe, DBfile, "reqdb")
{
	listView = l;
	keylist = keyl;
	loadContainer();
	reqicon[0] = loadImg("req.png");
        reqicon[1] = loadImg("reqkey.png");
	connect(keyl, SIGNAL(delKey(pki_key *)), this, SLOT(delKey(pki_key *)));
	connect(keyl, SIGNAL(newKey(pki_key *)), this, SLOT(newKey(pki_key *)));
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


void db_x509req::delKey(pki_key *delkey)
{
	pki_x509req *pki;
	CERR <<"delKey in X509req"<<endl;
	if ( container.isEmpty() ) return ;
	QListIterator<pki_base> iter(container); 
	for ( ; iter.current(); ++iter ) { // find the key of the request
		pki = (pki_x509req *)iter.current();
		if (pki->getKey() == delkey) {
			pki->setKey(NULL);
			updateViewPKI(pki);
		}
	}
}


void db_x509req::newKey(pki_key *newkey)
{
	pki_key *refkey;
	pki_x509req *pki;
	CERR <<"newKey in X509req"<<endl;
	if ( container.isEmpty() ) return ;
	QListIterator<pki_base> iter(container); 
	for ( ; iter.current(); ++iter ) { // find the key of the request
		pki = (pki_x509req *)iter.current();
		refkey = pki->getPubKey(); 
		if (refkey->compare(newkey)) {
			pki->setKey(newkey);
			updateViewPKI(pki);
		}
	}
}

void db_x509req::updateViewPKI(pki_base *pki)
{
        db_base::updateViewPKI(pki);
        if (! pki) return;
        int pixnum = 0;
        QListViewItem *current = (QListViewItem *)pki->getPointer();
        if (!current) return;
	if (((pki_x509req *)pki)->getKey() != NULL ) pixnum += 1;	
	current->setPixmap(0, *reqicon[pixnum]);
}

void db_x509req::preprocess()
{
	pki_x509req *pki;
	CERR <<"preprocess X509req"<<endl;
	if ( container.isEmpty() ) return ;
	QListIterator<pki_base> iter(container); 
	for ( ; iter.current(); ++iter ) { // find the key of the request
		pki = (pki_x509req *)iter.current();
		findKey(pki);
		CERR << "Key of "<< pki->getDescription().c_str() << endl;
	}
}


pki_key *db_x509req::findKey(pki_x509req *req)
{
	pki_key *key, *refkey;
	if (!req) return NULL;
	if ((key = req->getKey()) != NULL ) return key;
	refkey = req->getPubKey();
	key = (pki_key *)keylist->findPKI(refkey);
	if (key && key->isPubKey()) {
		key = NULL;
	}
	req->setKey(key);
	delete(refkey);
	return key;
}
