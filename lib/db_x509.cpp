/* vi: set sw=4 ts=4: */
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
#include <qmessagebox.h>

#define FOR_ctr(container) for (pki_x509 *pki = (pki_x509 *)container.first(); \
                        pki != 0; pki = (pki_x509 *)container.next() ) 
			

db_x509::db_x509(DbEnv *dbe, QString DBfile, db_key *k, DbTxn *tid, XcaListView *lvi)
	:db_x509super(dbe, DBfile, "certdb", k, tid, lvi)
{
	loadContainer();
	// FIXME:
	// connect(keyl, SIGNAL(delKey(pki_key *)), this, SLOT(delKey(pki_key *)));
	// connect(keyl, SIGNAL(newKey(pki_key *)), this, SLOT(newKey(pki_key *)));
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
		return client;
	}
	FOR_ctr(container)
		if (client->verify(pki)) 
			return pki;
	return NULL;
}

QStringList db_x509::getPrivateDesc()
{
	QStringList x;
	FOR_ctr(container)
		if (pki->getRefKey())
			x.append(pki->getIntName());	
	return x;
}

QStringList db_x509::getSignerDesc()
{
	QStringList x;
	FOR_ctr(container)
		if (pki->canSign())
			x.append(pki->getIntName());	
	return x;
}


void db_x509::remFromCont(pki_base *ref)
{
	container.remove(ref);
	FOR_ctr(container)
		pki->delSigner((pki_x509 *)ref);
	return;
}

void db_x509::preprocess()
{
	QList<pki_base> conta = container;
	FOR_ctr(conta) {
		findSigner(pki);
		findKey(pki);	
	}
	calcEffTrust();
	
}


void db_x509::calcEffTrust()
{
	FOR_ctr(container)
		pki->calcEffTrust();
}

	
void db_x509::insertPKI(pki_base *refpki)
{
	db_base::insertPKI(refpki);
	pki_x509 *x = (pki_x509 *)refpki;
	findSigner(x);
	findKey(x);
	FOR_ctr(container)
		pki->verify(x);
	calcEffTrust();
}				


QList<pki_x509> db_x509::getIssuedCerts(const pki_x509 *issuer)
{
	QList<pki_x509> c;
	c.clear();
	if (!issuer) return c;
	FOR_ctr(container)
		if (pki->getSigner() == issuer)
			c.append(pki);
	return c;
}

pki_x509 *db_x509::getBySubject(const x509name &xname, pki_x509 *last)
{
	bool lastfound = false;
	if (last == NULL) lastfound = true;
	
	FOR_ctr(container) {
		if ( pki->getSubject() ==  xname) {
			if (lastfound) {
				return pki;
			}
		}
		if (pki == last) {
			lastfound = true;
		}
	}
	return NULL;
}

void db_x509::revokeCert(const x509rev &revok, const pki_x509 *iss)
{
	pki_x509 *crt = getByIssSerial(iss, revok.getSerial());
	if (crt)
		crt->setRevoked(revok.getDate());
}
	
pki_x509 *db_x509::getByIssSerial(const pki_x509 *issuer, const a1int &a)
{
	if (!issuer ) return NULL;
	FOR_ctr(container)
		if ((pki->getSigner() == issuer) && (a == pki->getSerial()))
			return pki;
	return NULL;
}

void db_x509::writeAllCerts(const QString fname, bool onlyTrusted)
{
	FOR_ctr(container) {
		if (onlyTrusted && pki->getTrust() != 2) continue;
		pki->writeCert(fname.latin1(),true,true);
	}
}

QList<pki_x509> db_x509::getCerts(bool onlyTrusted)
{
	QList<pki_x509> c;
	c.clear();
	FOR_ctr(container) {
		if (onlyTrusted && pki->getTrust() != 2) continue;
		c.append(pki);
	}
	return c;
}

a1int db_x509::searchSerial(pki_x509 *signer)
{
	// returns the highest certificate serial
	// of all certs with this signer (itself too)
	a1int sserial, myserial; 
	if (!signer) return sserial;
	sserial = signer->getCaSerial();
	FOR_ctr(container)
		if (pki->getSigner() == signer)  {
			myserial = pki->getSerial();
			if (sserial < myserial ) {
				sserial = myserial;
			}
		}
	return sserial;
}

pki_base *db_x509::insert(pki_base *item)
{
	pki_x509 *cert = (pki_x509 *)item;
	pki_x509 *oldcert = (pki_x509 *)getByReference(cert);
	if (oldcert) {
		QMessageBox::information(NULL, XCA_TITLE,
		tr("The certificate already exists in the database as") +":\n'" +
		oldcert->getIntName() +
		"'\n" + tr("and so it was not imported"), "OK");
		delete(cert);
		return oldcert;
	}
	cert->setCaSerial((cert->getSerial()));
	insertPKI(cert);
	a1int serial;

	// check the CA serial of the CA of this cert to avoid serial doubles
	if (cert->getSigner() != cert && cert->getSigner()) {
		serial = cert->getSerial();
		if (cert->getSigner()->getCaSerial() < ++serial ) {
			cert->getSigner()->setCaSerial(serial);
			updatePKI(cert->getSigner());
		}
	}
	
	// check CA serial of this cert
	serial = searchSerial(cert);
	if ( ++serial > cert->getCaSerial()) {
		cert->setCaSerial(serial);
	}
	updatePKI(cert);
	return cert;
}

#undef FOR_ctr
