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


#include "pki_pkcs12.h"
#include "pass_info.h"
#include "exception.h"
#include <openssl/err.h>
#include <qmessagebox.h>


pki_pkcs12::pki_pkcs12(const QString d, pki_x509 *acert, pki_key *akey, pem_password_cb *cb):
	pki_base(d)
{
	class_name="pki_pkcs12";
	key = new pki_key(akey);
	cert = new pki_x509(acert);
	certstack = sk_X509_new_null();
	passcb = cb;
	openssl_error();	
}

pki_pkcs12::pki_pkcs12(const QString fname, pem_password_cb *cb)
	:pki_base(fname)
{ 
	FILE *fp;
	char pass[30];
	EVP_PKEY *mykey = NULL;
	X509 *mycert = NULL;
	key=NULL; cert=NULL;
	passcb = cb;
	class_name="pki_pkcs12";
	certstack = sk_X509_new_null();
	pass_info p(XCA_TITLE, tr("Please enter the password to decrypt the PKCS#12 file.")
		+ "\n'" + fname + "'");
	fp = fopen(fname, "rb");
	if (fp) {
		PKCS12 *pkcs12 = d2i_PKCS12_fp(fp, NULL);
		fclose(fp);
		openssl_error();
		if (passcb(pass, 30, 0, &p) == 0) {
			if (pass[0] != '\0') {
				/* cancel pressed */
				PKCS12_free(pkcs12);
				throw errorEx("","");
			}
		}
		PKCS12_parse(pkcs12, pass, &mykey, &mycert, &certstack);
		if ( ERR_peek_error() != 0) {
			ign_openssl_error();
			//QMessageBox::warning(NULL, XCA_TITLE, 
			//	tr(), tr("&OK"));
			PKCS12_free(pkcs12);
			throw errorEx(getClassName(),"The supplied password was wrong");
		}

		openssl_error();
		if (mykey) {
			key = new pki_key(mykey);
		}
		if (mycert) {
			cert = new pki_x509(mycert);
			cert->autoIntName();
		}
		PKCS12_free(pkcs12);
	}
	else fopen_error(fname);
}	

pki_pkcs12::~pki_pkcs12()
{
	if (sk_X509_num(certstack)>0) {
		// free the certs itself, because we own a copy of them
		sk_X509_pop_free(certstack, X509_free);
	}
	if (key) { 
		delete(key); 
	}
	if (cert) {
		delete(cert);
	}
	openssl_error();
}


void pki_pkcs12::addCaCert(pki_x509 *ca)
{ 
	if (!ca) return;
	sk_X509_push(certstack, X509_dup(ca->getCert()));
	openssl_error();
}	

void pki_pkcs12::writePKCS12(const QString fname)
{ 
	char pass[30];
	char desc[100];
	strncpy(desc,getIntName(),100);
	pass_info p(XCA_TITLE, tr("Please enter the password to encrypt the PKCS#12 file"));
	if (cert == NULL || key == NULL) {
		openssl_error("No key or no Cert and no pkcs12....");
	}

	FILE *fp = fopen(fname,"wb");
	if (fp != NULL) {
		passcb(pass, 30, 0, &p); 
		PKCS12 *pkcs12 = PKCS12_create(pass, desc, key->getKey(),
			cert->getCert(), certstack, 0, 0, 0, 0, 0);
		i2d_PKCS12_fp(fp, pkcs12);
		openssl_error();
		fclose (fp);
		PKCS12_free(pkcs12);
	}
	else fopen_error(fname);
}

int pki_pkcs12::numCa() {
	int n= sk_X509_num(certstack);
	openssl_error();
	return n;
}


pki_key *pki_pkcs12::getKey() {
	if (!key) return NULL;
	return new pki_key(key);
}


pki_x509 *pki_pkcs12::getCert() {
	if (!cert) return NULL;
	pki_x509 *c = new pki_x509(cert);
	c->autoIntName();
	return c;
}

pki_x509 *pki_pkcs12::getCa(int x) {
	pki_x509 *cert = NULL;
	X509 *crt = X509_dup(sk_X509_value(certstack, x));
	if (crt) {
		cert = new pki_x509(crt);
		cert->autoIntName();
	}
	openssl_error();
	return cert;
}

