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



#include "pki_x509.h"
#include "func.h"
#include "x509name.h"

QPixmap *pki_x509req::icon[2] = { NULL, NULL };

pki_x509req::pki_x509req() 
	: pki_x509super()
{
	privkey = NULL;
	class_name = "pki_x509req";
	request = X509_REQ_new();
	openssl_error();
}

void pki_x509req::createReq(pki_key *key, const x509name &dn, const EVP_MD *md)
{
	if (key->isPubKey()) {
		openssl_error("key not valid");
		return;
	}
	openssl_error();
	X509_REQ_set_version(request, 0L);
	X509_REQ_set_pubkey(request, key->getKey());
	X509_REQ_get_subject_name(request) = dn.get();
	openssl_error();
	X509_REQ_sign(request,key->getKey(), md);
	openssl_error();
}

pki_x509req::~pki_x509req()
{
	if (request)
		X509_REQ_free(request);
	openssl_error();
}


pki_x509req::pki_x509req(const QString fname)
	: pki_x509super()
{
	privkey = NULL;
	icon[0] = loadImg("req.png");
	icon[1] = loadImg("reqkey.png");
	class_name = "pki_x509req";
	FILE *fp = fopen(fname.latin1(),"r");
	if (fp != NULL) {
	   request = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
	   if (!request) {
		ign_openssl_error();
		rewind(fp);
		CERR("Fallback to private key DER"); 
	   	request = d2i_X509_REQ_fp(fp, NULL);
		openssl_error();
	   }
	   openssl_error();
	autoIntName();
	if (getIntName().isEmpty())
	   setIntName(rmslashdot(fname));
	}	
	else fopen_error(fname);
	fclose(fp);
	
}

void pki_x509req::fromData(unsigned char *p, int size)
{
	privkey = NULL;
	request = d2i_X509_REQ(&request, &p, size);
	openssl_error();
}

x509name pki_x509req::getSubject() const
{
	x509name x(X509_REQ_get_subject_name(request));
	openssl_error();
	return x;
}

unsigned char *pki_x509req::toData(int *size)
{
	unsigned char *p, *p1;
	*size = i2d_X509_REQ(request, NULL);
	openssl_error();
	p = (unsigned char*)OPENSSL_malloc(*size);
	p1 = p;
	i2d_X509_REQ(request, &p1);
	openssl_error();
	return p;
}

void pki_x509req::writeReq(const QString fname, bool PEM)
{
	FILE *fp = fopen(fname.latin1(),"w");
	if (fp != NULL) {
	   if (request){
		if (PEM) 
		   PEM_write_X509_REQ(fp, request);
		else
		   i2d_X509_REQ_fp(fp, request);
	        openssl_error();
	   }
	}
	else fopen_error(fname);
	fclose(fp);
}

bool pki_x509req::compare(pki_base *refreq)
{
	if (!refreq) return false;
	const EVP_MD *digest=EVP_md5();
	unsigned char d1[EVP_MAX_MD_SIZE], d2[EVP_MAX_MD_SIZE];	
	unsigned int d1_len,d2_len;
	X509_REQ_digest(request, digest, d1, &d1_len);
	X509_REQ_digest(((pki_x509req *)refreq)->request, digest, d2, &d2_len);
	ign_openssl_error();
	if ((d1_len == d2_len) && 
	    (d1_len >0) &&
	    (memcmp(d1,d2,d1_len) == 0) )return true;
	return false;
}
	
int pki_x509req::verify()
{
	 EVP_PKEY *pkey = X509_REQ_get_pubkey(request);
	 bool x = (X509_REQ_verify(request,pkey) != 0);
	 EVP_PKEY_free(pkey);
	 openssl_error();
	 return x;
}

pki_key *pki_x509req::getPubKey()
{
	 EVP_PKEY *pkey = X509_REQ_get_pubkey(request);
	 pki_key *key = new pki_key(pkey);	
	 openssl_error();
	 return key;
}

void pki_x509req::updateView()
{
	pki_base::updateView();
	if (! pointer) return;
	int pixnum = 0;
	if (getRefKey() != NULL ) pixnum += 1;
	pointer->setPixmap(0, *icon[pixnum]);
	pointer->setText(1, getSubject().getEntryByNid(NID_commonName));
}

QString pki_x509req::getSigAlg()
{
	QString alg = OBJ_nid2ln(OBJ_obj2nid(request->sig_alg->algorithm));
	return alg;
}
