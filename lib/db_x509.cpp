#include "db_x509.h"


db_x509::db_x509(DbEnv *dbe, string DBfile, string DB, QListView *l, db_key *keyl)
		:db_base(dbe, DBfile, DB, l)
{
	keylist = keyl;
	loadContainer();
	updateView();
}

pki_base *db_x509::newPKI(){
	return new pki_x509();
}

pki_x509 *db_x509::findsigner(pki_x509 *client)
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
	pm[0] = new QPixmap("validcert.png");
        pm[1] = new QPixmap("invalidcert.png");
        pm[2] = new QPixmap("validcertkey.png");
        pm[3] = new QPixmap("invalidcertkey.png");
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
			signer = findsigner(pki);
			cerr << "ARound "<< pki <<" - "<< signer << endl;
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
			cerr << "ARound "<< pki <<" - "<< signer << endl;
				pki->setPointer(current);
			cerr << "ARound "<< pki <<" - "<< signer << endl;
				pki_key *key= (pki_key *)keylist->findPKI(pki->getKey());
			cerr << "ARound "<< pki <<" - "<< signer << endl;
				int pixnum = 0;
				if (key)
 				   if (key->isPrivKey()) pixnum += 2;	
				if (signer == NULL) pixnum += 1 ;
				else if (signer->getSigner() == NULL) pixnum += 1;
			cerr << "ARound "<< pki <<" - "<< signer << endl;
				current->setPixmap(0, *pm[pixnum]);
				mycont.remove(pki);
			cerr << "ARound "<< pki <<" - "<< signer << endl;
				it.toFirst();
			cerr << "ARound "<< pki <<" - "<< signer << endl;
				cerr << "CRound " <<endl;
			}
		}
				
	}				
	return true;
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
