/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */                           


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
	listView->addColumn(tr("Common Name"));
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
	current->setText(1, ((pki_x509 *)pki)->getDNs(NID_commonName).c_str());
	current->setText(2, truststatus[((pki_x509 *)pki)->getTrust() ]);  
	if ( ((pki_x509 *)pki)->isRevoked() ){ 
		current->setText(3, tr("Revoked"));
	}
	else {
		current->setText(3, "");
	}
	keylist->updateView();
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

QStringList db_x509::getSignerDesc()
{
	pki_x509 *pki;
	QStringList x;
        if ( container.isEmpty() ) return x;
        for ( pki = (pki_x509 *)container.first(); pki != 0; pki = (pki_x509 *)container.next() ) {
		if (pki->canSign())
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
	if (cert->setKey(key)) keylist->updateViewPKI(key);
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
				if (pki->setKey(newkey)) keylist->updateViewPKI(newkey);
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
		keylist->updateView();
	}
	return s;
}				

void db_x509::assignClients(pki_crl *crl)
{
	if (!crl) return;
	pki_x509 *issuer = crl->getIssuer();
	pki_x509 *cert = NULL;
	if (!issuer) return;
       	for ( cert = (pki_x509 *)container.first(); cert != 0; cert = (pki_x509 *)container.next() ) {
		if ((cert->getSigner() == issuer) && (cert->isRevoked())) {
			crl->addRevoked(cert);
		}
	}
}

