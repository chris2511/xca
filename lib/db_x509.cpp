#include "db_x509.h"


db_x509::db_x509(DbEnv *dbe, string DBfile, QListView *l, db_key *keyl)
		:db_base(dbe, DBfile, "certdb")
{
	keylist = keyl;
	listView = l;
	loadContainer();
	updateView();
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
	QString path = PREFIX;
	path += "/share/xca/";
	cerr << "PATH=" << path << endl;
	pm[0] = new QPixmap(path + "validcert.png");
        pm[1] = new QPixmap(path + "invalidcert.png");
        pm[2] = new QPixmap(path + "validcertkey.png");
        pm[3] = new QPixmap(path + "invalidcertkey.png");
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
				if (findKey(pki)) pixnum += 2;	
				if (!signer) pixnum += 1 ;
				else if (!signer->getSigner() ) pixnum += 1;
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
	pki_key *key;
	key = (pki_key *)keylist->findPKI(cert->getKey());
	if (key)
 	  if (key->isPubKey())
		key = NULL;
	
	return key;
}


