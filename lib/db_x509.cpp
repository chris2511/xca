#include "db_x509.h"


db_x509::db_x509(DbEnv *dbe, string DBfile, QListView *l, db_key *keyl)
		:db_base(dbe, DBfile, "certdb")
{
	keylist = keyl;
	listView = l;
	loadContainer();
	updateView();
	connect(keyl, SIGNAL(delKey(pki_key *)), this, SLOT(delKey(pki_key *)));
	connect(keyl, SIGNAL(newKey(pki_key *)), this, SLOT(newKey(pki_key *)));
}

pki_base *db_x509::newPKI(){
	return new pki_x509();
}

pki_x509 *db_x509::findSigner(pki_x509 *client)
{
        pki_x509 *signer;
	if ((signer = client->getSigner()) != NULL) return signer;
	QListIterator<pki_base> it(container); 
	for ( ; it.current(); ++it ) {
		signer = (pki_x509 *)it.current();
		if (client->verify(signer)) {
			cerr << "SIGNER found" <<endl;
			return signer;
		}
	}		
	
	return NULL;
}

bool db_x509::updateView()
{
        listView->clear();
	listView->setRootIsDecorated(true);
        QPixmap *pm[4];
	pm[0] = loadImg("validcert.png");
        pm[1] = loadImg("invalidcert.png");
        pm[2] = loadImg("validcertkey.png");
        pm[3] = loadImg("invalidcertkey.png");
	pki_x509 *pki;
	pki_x509 *signer;
	QListViewItem *parentitem;
	QListViewItem *current;
	cerr <<"myupdate"<<endl;
	if ( container.isEmpty() ) return false;
	QList<pki_base> mycont = container;
	for ( pki = (pki_x509 *)container.first(); pki != NULL; pki = (pki_x509 *)container.next() ) pki->delPointer();
	int f=0;
	while (! mycont.isEmpty() ) {
		cerr << "-----------------------------------------------------------------Round "<< f++ <<endl;
		QListIterator<pki_base> it(mycont); 
		for ( ; it.current(); ++it ) {
			pki = (pki_x509 *)it.current();
			parentitem = NULL;
			signer = findSigner(pki);
			if ((signer != pki) && (signer != NULL)) // foreign signed
				parentitem = (QListViewItem *)signer->getPointer();
			if (((parentitem != NULL) || (signer == pki) || (signer == NULL)) && (pki->getPointer() == NULL )) {
				// create the listview item
				if (parentitem != NULL) {
					current = new QListViewItem(parentitem, pki->getDescription().c_str());	
					cerr<< "Adding as client: "<<pki->getDescription().c_str()<<endl;
				}
				else {
					current = new QListViewItem(listView, pki->getDescription().c_str());	
					cerr<< "Adding as parent: "<<pki->getDescription().c_str()<<endl;
				}
				pki->setPointer(current);
				int pixnum = 0;
				if (pki->getTrust() == 0){ // Never Trust it
					pixnum += 1;
				}	
				else if (pki->getTrust() == 1) { // Trust it, if we trust parent
					if (signer == pki ) pixnum += 1; // self signed
					else if (!signer) pixnum += 1 ; // no signer
					else if (!signer->getEffTrust()) pixnum += 1 ; // no trust of parent
				}
				if (pixnum == 0) pki->setEffTrust(true);
				else pki->setEffTrust(false); // remember the effektive truststate	
				if (findKey(pki)) pixnum += 2;	
				// if pki->getTrust() == 2 trust it always
				current->setPixmap(0, *pm[pixnum]);
				mycont.remove(pki);
				it.toFirst();
			}
		}
				
	}				
	return true;
}


QStringList db_x509::getPrivateDesc()
{
	pki_x509 *pki;
	QStringList x;
        if ( container.isEmpty() ) return x;
        for ( pki = (pki_x509 *)container.first(); pki != 0; pki = (pki_x509 *)container.next() ) {
		if (findKey(pki))
		x.append(pki->getDescription().c_str());	
	}
	return x;
}


void db_x509::remFromCont(pki_base *pki)
{
        container.remove(pki);
 	pki_x509 *pkiit;
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pkiit = (pki_x509 *)it.current();
		if (pkiit->getSigner()==pki) {
			pkiit->delSigner();
		}
	}
	return;
}

pki_key *db_x509::findKey(pki_x509* cert)
{
	if (!cert) return NULL;
	pki_key *key;
	key = (pki_key *)keylist->findPKI(cert->getKey());
	if (key)
 	  if (key->isPubKey())
		key = NULL;
	
	return key;
}

void db_x509::delKey(pki_key *delkey)
{
	updateView();
}


void db_x509::newKey(pki_key *newkey)
{
	updateView();
}

