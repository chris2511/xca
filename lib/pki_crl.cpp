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


#include "pki_crl.h"

QPixmap *pki_crl::icon = NULL;

pki_crl::pki_crl(const QString fname )
	:pki_base(fname)
{ 
	issuer = NULL;
	crl = X509_CRL_new();
	class_name="pki_crl";
	FILE * fp = fopen(fname, "r");
	if (fp != NULL) {
		crl = PEM_read_X509_CRL(fp, &crl, NULL, NULL);
		if (!crl) {
			ign_openssl_error();
			rewind(fp);
			crl = d2i_X509_CRL_fp(fp, &crl);
		}	
		fclose(fp);
		setIntName(rmslashdot(fname));
		openssl_error();
	}
	else fopen_error(fname);
}

pki_crl::pki_crl()
	:pki_base()
{
	issuer = NULL;
	a1int version = 1; /* version 2 CRL */
	crl = X509_CRL_new();
	class_name="pki_crl";
#if OPENSSL_VERSION_NUMBER >= 0x0090700fL	
	crl->crl->revoked = sk_X509_REVOKED_new_null();
#endif
	crl->crl->version = version.get();
	openssl_error();
}

void pki_crl::createCrl(const QString d, pki_x509 *iss )
{ 
	setIntName(d);
	issuer = iss;
	if (!iss) openssl_error("no issuer");
	openssl_error();
	crl->crl->issuer = issuer->getSubject().get();
	openssl_error();
}	

a1int pki_crl::getVersion()
{
	a1int a(crl->crl->version);
	return a;
}

void pki_crl::setLastUpdate(const a1time &t)
{
	if (crl->crl->lastUpdate != NULL)
		ASN1_TIME_free(crl->crl->lastUpdate);
	
	crl->crl->lastUpdate = t.get();
}

void pki_crl::setNextUpdate(const a1time &t)
{
	if (crl->crl->nextUpdate != NULL)
		ASN1_TIME_free(crl->crl->nextUpdate);
	
	crl->crl->nextUpdate = t.get();
}

pki_crl::~pki_crl()
{
	X509_CRL_free(crl);
}

void pki_crl::fromData(unsigned char *p, int size)
{
	crl = NULL;
	crl = d2i_X509_CRL(NULL, &p, size);
	openssl_error();
}

unsigned char *pki_crl::toData(int *size)
{
	unsigned char *p, *p1;
	*size = i2d_X509_CRL(crl, NULL);
	openssl_error();
	p = (unsigned char*)OPENSSL_malloc(*size);
	p1 = p;
	i2d_X509_CRL(crl, &p1);
	openssl_error();
	return p;
}

bool pki_crl::compare(pki_base *refcrl)
{
	bool ret;
	ret = X509_CRL_cmp(crl, ((pki_crl *)refcrl)->crl) == 0 && 
		getLastUpdate() == ((pki_crl *)refcrl)->getLastUpdate() &&
		getNextUpdate() == ((pki_crl *)refcrl)->getNextUpdate() ;
	openssl_error();
	return ret;
}


void pki_crl::addRev(const x509rev &xrev)
{
	sk_X509_REVOKED_push(crl->crl->revoked, xrev.get());
	openssl_error();
}

void pki_crl::addV3ext(const x509v3ext &e)
{ 
	X509_EXTENSION *ext = e.get();
	X509_CRL_add_ext(crl, ext, -1);
	X509_EXTENSION_free(ext);
	openssl_error();
}


void pki_crl::sign(pki_key *key, const EVP_MD *md)
{
	if (!key || key->isPubKey()) return;
	X509_CRL_sign(crl, key->key, md);
	openssl_error();
}


void pki_crl::writeCrl(const QString fname, bool pem)
{
	FILE *fp = fopen(fname,"w");
	if (fp != NULL) {
	   if (crl){
		CERR("writing CRL");
		if (pem)
			PEM_write_X509_CRL(fp, crl);
		else
			i2d_X509_CRL_fp(fp, crl);
		openssl_error();
	   }
	}
	else fopen_error(fname);
	fclose(fp);
}

pki_x509 *pki_crl::getIssuer() { return issuer; }

a1time pki_crl::getLastUpdate()
{
	a1time a;
	if (!crl || !crl->crl) return a;
	a.set(crl->crl->lastUpdate);
	return a;
}

a1time pki_crl::getNextUpdate()
{
	a1time a;
	if (!crl || !crl->crl) return a;
	a.set(crl->crl->nextUpdate);
	return a;
}

int pki_crl::numRev()
{
	if (crl && crl->crl && crl->crl->revoked)
		return sk_X509_REVOKED_num(crl->crl->revoked);
	else
		return 0;
}

x509rev pki_crl::getRev(int num)
{
	x509rev ret;
	if (crl && crl->crl && crl->crl->revoked) {
		ret.set(sk_X509_REVOKED_value(crl->crl->revoked, num));
		openssl_error();
	}
	return ret;
}	

x509name pki_crl::getIssuerName()
{
	x509name x;
	if (crl && crl->crl && crl->crl->issuer) {
		x.set(crl->crl->issuer);
	}
	return x ;
}

bool pki_crl::verify(pki_key *key)
{
	bool ret=false;
	if (crl && crl->crl && key) {
		ret = (X509_CRL_verify(crl , key->key) == 1);
		ign_openssl_error();
	}
	return ret ;
}	

QString pki_crl::printV3ext()
{
	extList el;
	el.setStack(crl->crl->extensions);
	QString text = el.getHtml("<br>");
	openssl_error();
	return text;
}

void pki_crl::updateView()
{
	QListViewItem *c = getLvi();
	if (!c) return;
	c->setPixmap(0, *icon);
	c->setText(1, getIssuerName().getEntryByNid(NID_commonName));
	c->setText(2, QString::number(numRev()));
}

