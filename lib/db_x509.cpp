#include "db_x509.h"


db_x509::db_x509(DbEnv *dbe, string DBfile, QListView *l, db_key *keyl)
		:db_base(dbe, DBfile, "certdb")
{
	keylist = keyl;
	listView = l;
	certicon[0] = loadImg("validcert.png");
        certicon[1] = loadImg("validcertkey.png");
        certicon[2] = loadImg("invalidcert.png");
        certicon[3] = loadImg("invalidcertkey.png");
	listView->addColumn(tr("Trust state"));
	listView->addColumn(tr("Revokation"));
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
	pki_x509 *pki;
	pki_base *pkib;
	pki_x509 *signer;
	QListViewItem *parentitem;
	QListViewItem *current;
	cerr <<"myupdate"<<endl;
	if ( container.isEmpty() ) return false;
	QList<pki_base> mycont = container;
	for ( pkib = container.first(); pkib != NULL; pkib = container.next() ) pkib->delPointer();
	int f=0;
	while (! mycont.isEmpty() ) {
		cerr << "-----------------------------------------------------------------Round "<< f++ <<endl;
		QListIterator<pki_base> it(mycont); 
		for ( ; it.current(); ++it ) {
			pki = (pki_x509 *)it.current();
			parentitem = NULL;
			signer = pki->getSigner();
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
				mycont.remove(pki);
				updateViewPKI(pki);
				it.toFirst();
			}
		}
				
	}				
	return true;
}

void db_x509::updateViewPKI(pki_base *pki)
{
	db_base::updateViewPKI(pki);
	if (! pki) return;
	QString truststatus[] = { tr("Not trusted"), tr("Trust inherited"), tr("Always Trusted") };
	int pixnum = 0;
	QListViewItem *current = (QListViewItem *)pki->getPointer();
	if (!current) return;
	if (((pki_x509 *)pki)->getKey()) {
		pixnum += 1;
	}
	if (((pki_x509 *)pki)->calcEffTrust() == 0){ 
		pixnum += 2;
	}	
	current->setPixmap(0, *certicon[pixnum]);
	current->setText(1, truststatus[((pki_x509 *)pki)->getTrust() ]);  
	if ( ((pki_x509 *)pki)->isRevoked() ){ 
		current->setText(2, tr("Revoked"));
	}
	else {
		current->setText(2, "");
	}
}


void db_x509::updateViewAll()
{
 	pki_x509 *pki;
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = (pki_x509 *)it.current();
		updateViewPKI(pki);
	}
	return;
}


QStringList db_x509::getPrivateDesc()
{
	pki_x509 *pki;
	QStringList x;
        if ( container.isEmpty() ) return x;
        for ( pki = (pki_x509 *)container.first(); pki != 0; pki = (pki_x509 *)container.next() ) {
		if (pki->getKey())
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
		if (pkiit->getSigner() == pki) {
			pkiit->delSigner();
		}
	}
	return;
}

pki_key *db_x509::findKey(pki_x509* cert)
{
	pki_key *key, *refkey;
	if (!cert) return NULL;
	if ((key = cert->getKey()) != NULL ) return key;
	refkey = cert->getPubKey();
	key = (pki_key *)keylist->findPKI(refkey);
	if (key && key->isPubKey()) {
		key = NULL;
	}
	cert->setKey(key);
	delete(refkey);
	return key;
}

void db_x509::delKey(pki_key *delkey)
{
	pki_x509 *pki;
        if ( container.isEmpty() ) return ;
        for ( pki = (pki_x509 *)container.first(); pki != 0; pki = (pki_x509 *)container.next() ) {
		if (pki->getKey() == delkey) {
			pki->delKey();
			updateViewPKI(pki);
		}
	}
	
}


void db_x509::newKey(pki_key *newkey)
{
	pki_x509 *pki;
	pki_key *refkey;
        if ( container.isEmpty() ) return ;
        for ( pki = (pki_x509 *)container.first(); pki != 0; pki = (pki_x509 *)container.next() ) {
		if (!pki->getKey()) { 
			refkey = pki->getPubKey();
			if (newkey->compare(refkey)) {
				pki->setKey(newkey);
				updateViewPKI(pki);
			}
			delete(refkey);
		}
	}
}

void db_x509::preprocess()
{
	pki_x509 *pki;
	CERR <<"preprocess X509"<<endl;
	if ( container.isEmpty() ) return ;
	QListIterator<pki_base> iter(container); 
	for ( ; iter.current(); ++iter ) { // find the signer and the key of the certificate...
		pki = (pki_x509 *)iter.current();
		findSigner(pki);
		CERR << "Signer of "<< pki->getDescription().c_str() << endl;
		findKey(pki);	
		CERR << "Key of "<< pki->getDescription().c_str() << endl;
	}
	CERR << "Signers and keys done "<< endl;
	
	calcEffTrust();
	
/*	
	pki_x509 *signer;
	while (! mycont.isEmpty() ) {
	    QListIterator<pki_base> it(mycont); 
	    for (it.toFirst(); it.current(); ++it ) {
		int trust = 1; // dont know
		pki = (pki_x509 *)it.current();
		signer = pki->getSigner();
		    CERR << "inloop " << pki->getDescription() <<endl;
	
		if (pki->getTrust() != 1){ // Always trust it or never
			trust = pki->getTrust();
		}	
		else if ( signer) { // Trust it, if we trust parent and there is a parent
			if (signer == pki) {  // if self signed
				trust = 0; // no trust
			}
			else {
				trust = signer->getEffTrust(); // inherit trustment of parent
			}
		}	
		else { // we do not trust an unknown signer
			trust=0;
		}
		if (trust != 1) { // trustment deterministic
			pki->setEffTrust(trust);
			mycont.remove(pki);
			it.toFirst();
		}
				
	    }
	}
	return ;
*/
}


void db_x509::calcEffTrust()
{
	pki_x509 *pki;
	CERR <<"re calc eff trust X509"<<endl;
	if ( container.isEmpty() ) return ;
	QListIterator<pki_base> iter(container); 
	for ( ; iter.current(); ++iter ) { // find the signer and the key of the certificate...
		pki = (pki_x509 *)iter.current();
		CERR << "CalcTrust for: " << pki->getDescription().c_str() << endl;
		pki->calcEffTrust();
	}
}

	
bool db_x509::insertPKI(pki_base *pki)
{
	bool s = db_base::insertPKI(pki);
	pki_x509 *cert, *x = (pki_x509 *)pki;
	if (s) {
		findSigner(x);
		findKey(x);
	        if ( container.isEmpty() ) return false;
        	for ( cert = (pki_x509 *)container.first(); cert != 0; cert = (pki_x509 *)container.next() ) {
			cert->verify(x);
		}
		calcEffTrust();
		updateView();
	}
	return s;
}				
