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
#define FOR_container for (pki_x509 *pki = (pki_x509 *)container.first(); \
                        pki != 0; pki = (pki_x509 *)container.next() ) 
			

db_x509::db_x509(DbEnv *dbe, string DBfile, QListView *l, db_key *keyl, DbTxn *tid)
		:db_base(dbe, DBfile, "certdb", tid)
{
	keylist = keyl;
	listView = l;
	certicon[0] = loadImg("validcert.png");
        certicon[1] = loadImg("validcertkey.png");
        certicon[2] = loadImg("invalidcert.png");
        certicon[3] = loadImg("invalidcertkey.png");
	listView->addColumn(tr("Common Name"));
	listView->addColumn(tr("Serial"));
	listView->addColumn(tr("not After"));
	listView->addColumn(tr("Trust state"));
	listView->addColumn(tr("Revokation"));
	loadContainer();
	viewState=1; // Tree View
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
	if (client->verify(client)) {
		CERR("SELF signed");
		return signer;
	}
	for ( ; it.current(); ++it ) {
		signer = (pki_x509 *)it.current();
		if (client->verify(signer)) {
			CERR("SIGNER found");
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
	CERR("myUPDATE");
	if ( container.isEmpty() ) return false;
	QList<pki_base> mycont = container;
	for ( pkib = container.first(); pkib != NULL; pkib = container.next() ) pkib->delPointer();
	int f=0;
	while (! mycont.isEmpty() ) {
		CERR("-----------------------------------------------------------------Round "<< f++);
		QListIterator<pki_base> it(mycont); 
		for ( ; it.current(); ++it ) {
			pki = (pki_x509 *)it.current();
			parentitem = NULL;
			signer = pki->getSigner();
			if ((signer != pki) && (signer != NULL) && (viewState != 0)) // foreign signed
				parentitem = (QListViewItem *)signer->getPointer();
			if (((parentitem != NULL) || (signer == pki) || (signer == NULL) || viewState == 0) && (pki->getPointer() == NULL )) {
				// create the listview item
				if (parentitem != NULL) {
					current = new QListViewItem(parentitem, pki->getDescription().c_str());	
					CERR("Adding as client: "<<pki->getDescription().c_str());
				}
				else {
					current = new QListViewItem(listView, pki->getDescription().c_str());	
					CERR("Adding as parent: "<<pki->getDescription().c_str());
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

QStringList db_x509::getPrivateDesc()
{
	QStringList x;
	FOR_container
		if (pki->getKey())
			x.append(pki->getIntName());	
	return x;
}

QStringList db_x509::getSignerDesc()
{
	QStringList x;
	FOR_container
		if (pki->canSign())
			x.append(pki->getIntName());	
	return x;
}


void db_x509::remFromCont(pki_base *ref)
{
        container.remove(ref);
	FOR_container
		pki->delSigner(ref);
	return;
}

void db_x509::preprocess()
{
	pki_x509 *pki;
	CERR("preprocess X509");
	if ( container.isEmpty() ) return ;
	QListIterator<pki_base> iter(container); 
	for ( ; iter.current(); ++iter ) { // find the signer and the key of the certificate...
		pki = (pki_x509 *)iter.current();
		findSigner(pki);
		CERR("Signer of "<< pki->getDescription().c_str());
		findKey(pki);	
		CERR("Key of "<< pki->getDescription().c_str());
	}
	CERR("Signers and keys done ");
	
	calcEffTrust();
	
}


void db_x509::calcEffTrust()
{
	// find the signer and the key of the certificate...
	FOR_container
		pki->calcEffTrust();
}

	
void db_x509::insertPKI(pki_base *refpki)
{
	db_base::insertPKI(refpki);
	pki_x509 *x = (pki_x509 *)refpki;
	findSigner(x);
	findKey(x);
	FOR_container
		cert->verify(x);
	calcEffTrust();
}				


QList<pki_x509> db_x509::getIssuedCerts(pki_x509 *issuer)
{
	QList<pki_x509> c;
	c.clear();
	if (!issuer) return c;
	FOR_container
		if (pki->getSigner() == issuer)
			c.append(cert);
	return c;
}

pki_x509 *db_x509::getBySubject(const x509name &xname)
{
	FOR_container
		if ( pki->getSubject ==  xname) 
			return pki;
	return NULL;
}

pki_x509 *db_x509::getByIssSerial(pki_x509 *iss, a1int &serial)
{
	if (!iss || serial == -1) return NULL;
	FOR_container
		if ((pki->getSigner() == iss) && (serial == pki->getSerial()))
			return pki;
	return NULL;
}

void db_x509::writeAllCerts(QString fname, bool onlyTrusted)
{
	pki_x509 *cert = NULL;
       	FOR_container {
		if (onlyTrusted && pki->getTrust() != 2) continue;
		pki->writeCert(fname.latin1(),true,true);
	}
}

QList<pki_x509> db_x509::getCerts(bool onlyTrusted)
{
	QList<pki_x509> c;
	c.clear();
	FOR_container {
		if (onlyTrusted && pki->getTrust() != 2) continue;
		c.append(pki);
	}
	return c;
}

a1int db_x509::searchSerial(pki_x509 *signer)
{
	if (!signer) return 0;
	a1int sserial = signer->getCaSerial();
	a1int oserial = 0;
	FOR_container
		if (pki->getSigner() == signer)  {
			myserial = pki->getSerial();
			if (sserial < myserial ) {
				sserial = myserial;
			}
		}
	return sserial;
}

#undef FOR_container
