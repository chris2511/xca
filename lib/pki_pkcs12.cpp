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


#include "pki_pkcs12.h"


pki_pkcs12::pki_pkcs12(const string d, pki_x509 *acert, pki_key *akey, pem_password_cb *cb):
	pki_base(d)
{
	key = new pki_key(akey);
	cert = new pki_x509(acert);
	certstack = sk_X509_new_null();
	pkcs12 = NULL;
	passcb = cb;
	openssl_error();	
	className="pki_pkcs12";
}

pki_pkcs12::pki_pkcs12(const string fname, pem_password_cb *cb)
	:pki_base(fname)
{ 
	FILE *fp;
	char pass[30];
	EVP_PKEY *mykey;
	X509 *mycert;
	key=NULL; cert=NULL; pkcs12=NULL;
	passcb = cb;
	certstack = sk_X509_new_null();
	PASS_INFO p;
	string title = XCA_TITLE;
	string description = "Please enter the password to encrypt the PKCS#12 file.";
	p.title = &title;
	p.description = &description;
	fp = fopen(fname.c_str(), "rb");
	if (fp) {
		pkcs12 = d2i_PKCS12_fp(fp, NULL);
		CERR("PK12");
		fclose(fp);
		openssl_error();
		passcb(pass, 30, 0, &p);
		CERR("PK12");
		PKCS12_parse(pkcs12, pass, &mykey, &mycert, &certstack);
		CERR("PK12");
		openssl_error();
		if (mykey) {
			key = new pki_key(mykey);
			key->setDescription("pk12-import");
			//EVP_PKEY_free(mykey);
		}
		if (mycert) {
			cert = new pki_x509(mycert);
			cert->setDescription("pk12-import");
			//X509_free(mycert);
		}
	}
	else fopen_error(fname);
	className="pki_pkcs12";
}	


pki_pkcs12::~pki_pkcs12()
{
	CERR("popping free certs");
	if (sk_X509_num(certstack)>0)
		sk_X509_pop_free(certstack, X509_free); // free the certs itself, because we own a copy of them
	CERR("deleting key");
	if (key) delete(key); 
	CERR( "deleting cert");
	if (cert) delete(cert);
	CERR("freeing PKCS12");
	PKCS12_free(pkcs12);
	openssl_error();
}


void pki_pkcs12::addCaCert(pki_x509 *ca)
{ 
	if (!ca) return;
	sk_X509_push(certstack, X509_dup(ca->getCert()));
	openssl_error();
}	

void pki_pkcs12::writePKCS12(const string fname)
{ 
	char pass[30];
	char desc[100];
	strncpy(desc,getDescription().c_str(),100);
	PASS_INFO p;
	string title = XCA_TITLE;
	string description = "Please enter the password to encrypt the PKCS#12 file";
	p.title = &title;
	p.description = &description;
	if (!pkcs12) {
		if (cert == NULL || key == NULL) {
			openssl_error("No key or no Cert and no pkcs12....");
		}
		passcb(pass, 30, 0, &p); 
		CERR( desc << key->getKey() << cert->getCert() );
		CERR("before PKCS12_create....");
		pkcs12 = PKCS12_create(pass, desc, key->getKey(), cert->getCert(), certstack, 0, 0, 0, 0, 0);
		openssl_error();
		CERR("after PKCS12_create....");
	}
	FILE *fp = fopen(fname.c_str(),"wb");
	if (fp != NULL) {
	    CERR("writing PKCS#12");
            i2d_PKCS12_fp(fp, pkcs12);
            openssl_error();
	    fclose (fp);
        }
	else fopen_error(fname);
}

int pki_pkcs12::numCa() {
	int n= sk_X509_num(certstack);
	openssl_error();
	return n;
}


pki_key *pki_pkcs12::getKey() {
	return new pki_key(key);
}


pki_x509 *pki_pkcs12::getCert() {
	return new pki_x509(cert);
}

pki_x509 *pki_pkcs12::getCa(int x) {
	pki_x509 *cert;
	cert = new pki_x509(X509_dup(sk_X509_value(certstack, x)));
	openssl_error();
	cert->setDescription("pk12-import");
	return cert;
}

