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


#include "db_x509req.h"


db_x509req::db_x509req(DbEnv *dbe, std::string DBfile, QListView *l, db_key *keyl)
		:db_base(dbe, DBfile, "reqdb")
{
	listView = l;
	keylist = keyl;
	loadContainer();
	reqicon[0] = loadImg("req.png");
        reqicon[1] = loadImg("reqkey.png");
	listView->addColumn(tr("Common Name"));
	connect(keyl, SIGNAL(delKey(pki_key *)), this, SLOT(delKey(pki_key *)));
	connect(keyl, SIGNAL(newKey(pki_key *)), this, SLOT(newKey(pki_key *)));
	updateView();
}

pki_base *db_x509req::newPKI(){
	return new pki_x509req();
}

void db_x509req::delKey(pki_key *delkey)
{
	pki_x509req *pki;
	CERR("delKey in X509req");
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
	CERR("newKey");
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
	current->setText(1, ((pki_x509req *)pki)->getDN(NID_commonName).c_str());
}

void db_x509req::preprocess()
{
	pki_x509req *pki;
	CERR("preprocess X509req");
	if ( container.isEmpty() ) return ;
	QListIterator<pki_base> iter(container); 
	for ( ; iter.current(); ++iter ) { // find the key of the request
		pki = (pki_x509req *)iter.current();
		findKey(pki);
		CERR("Key of "<< pki->getDescription().c_str());
	}
}


pki_key *db_x509req::findKey(pki_x509req *req)
{
	pki_key *key, *refkey;
	if (!req) return NULL;
	MARK
	if ((key = req->getKey()) != NULL ) return key;
	refkey = req->getPubKey();
	key = (pki_key *)keylist->findPKI(refkey);
	if (key && key->isPubKey()) {
		key = NULL;
	}
	if (req->setKey(key)) keylist->updateViewPKI(key);
	if (refkey) delete(refkey);
	return key;
}

void db_x509req::remFromCont(pki_base *pki)
{
        container.remove(pki);
	pki_key *pkey = ((pki_x509req *)pki)->getKey();
}

