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


#include "pki_pkcs7.h"


pki_pkcs7::pki_pkcs7(const std::string d )
	:pki_base(d)
{ 
	p7 = NULL;
	className="pki_pkcs7";
}	


pki_pkcs7::~pki_crl()
{
	PKCS7_free(p7);
}

void pki_pkcs7::signBio(pki_x509 *crt, BIO *bio)
{
	STACK_OF(X509) *certstack;
	pki_key *privkey;
	if (!crt) return;
	privkey = crt->getKey();
	if (!privkey) throw errorEx("No private key for signing found", className);
	certstack = sk_X509_new_null();
	pki_x509 *signer = crt->getSigner();
	while (signer != NULL && signer != crt) {
		sk_X509_push(certstack, signer->getCert());
	        openssl_error();
		signer = signer->getSigner();
	}
	p7 = PKCS7_sign(crt, privkey, certstack, bio, 0);
	openssl_error();	
	sk_X509_free(certstack);
}


void pki_pkcs7::signFile(pki_x509 *crt, std::string filename)
{
	BIO *bio = NULL;
	if (!crt) return;
	bio = BIO_new_file(filename.c_str(), "r");
        openssl_error();
	signBio(crt, bio);
	BIO_free(bio);
}
	
void pki_pkcs7::signCert(pki_x509 *crt, pki_x509 *contCert)
{
	BIO *bio = NULL;
	if (!crt) return;
	bio = BIO_new(BIO_s_mem());
        openssl_error();
	i2d_X509_bio(bio, contCert);
	signBio(crt, bio);
	BIO_free(bio);
}

void pki_pkcs7::writeP7(string fname,bool PEM)
{

