#include "db_x509.h"


db_x509::db_x509(DbEnv *dbe, string DBfile, string DB, QListView *l)
		:db_base(dbe, DBfile, DB, l)
{
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
			if (signer == NULL); // do something for unknown signers...
			if (((parentitem != NULL) || (signer == pki) || (signer == NULL)) && (pki->getPointer() == 0 )) {
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
				mycont.remove(pki);
				it.toFirst();
				listView->setOpen(current, true);
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
			return;
		}
	}
	return;
}
