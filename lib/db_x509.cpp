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
		:db_x509super(dbe, DBfile, "certdb", keyl, tid)
{
	loadContainer();
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
	// first check for self-signed
	if (client->verify(client)) {
		return signer;
	}
	FOR_container
		if (client->verify(pki)) 
			return signer;
	return NULL;
}

QStringList db_x509::getPrivateDesc()
{
	QStringList x;
	FOR_container
		if (pki->getRefKey())
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
		pki->delSigner((pki_x509 *)ref);
	return;
}

void db_x509::preprocess()
{
	FOR_container {
		findSigner(pki);
		findKey(pki);	
	}
	calcEffTrust();
	
}


void db_x509::calcEffTrust()
{
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
		pki->verify(x);
	calcEffTrust();
}				


QList<pki_x509> db_x509::getIssuedCerts(pki_x509 *issuer)
{
	QList<pki_x509> c;
	c.clear();
	if (!issuer) return c;
	FOR_container
		if (pki->getSigner() == issuer)
			c.append(pki);
	return c;
}

pki_x509 *db_x509::getBySubject(const x509name &xname)
{
	FOR_container
		if ( pki->getSubject() ==  xname) 
			return pki;
	return NULL;
}

pki_x509 *db_x509::getByIssSerial(pki_x509 *iss, a1int &serial)
{
	if (!iss ) return NULL;
	FOR_container
		if ((pki->getSigner() == iss) && (serial == pki->getSerial()))
			return pki;
	return NULL;
}

void db_x509::writeAllCerts(QString fname, bool onlyTrusted)
{
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
	a1int myserial;
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
