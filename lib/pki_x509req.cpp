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

void pki_x509req::init()
{
	request = NULL;
	privkey = NULL;
	className = "pki_x509req";
}


pki_x509req::pki_x509req(pki_key *key, const string cn,
		const string c, const string l,
		const string st,const string o,
		const string ou,const string email, 
		const string d, const string challenge)
		:pki_base( d )
{
	init();
	
	X509_NAME *subj = X509_NAME_new();
	if (cn != "")
	X509_NAME_add_entry_by_NID(subj,NID_commonName, MBSTRING_ASC,
		(unsigned char*)cn.c_str(),-1,-1,0);
	if (c != "")
	X509_NAME_add_entry_by_NID(subj,NID_countryName, MBSTRING_ASC, 
		(unsigned char*)c.c_str() , -1, -1, 0);
	if (l != "")
	X509_NAME_add_entry_by_NID(subj,NID_localityName, MBSTRING_ASC, 
		(unsigned char*)l.c_str() , -1, -1, 0);
	if (st != "")
	X509_NAME_add_entry_by_NID(subj,NID_stateOrProvinceName, MBSTRING_ASC, 
		(unsigned char*)st.c_str() , -1, -1, 0);
	if (o != "")
	X509_NAME_add_entry_by_NID(subj,NID_organizationName, MBSTRING_ASC, 
		(unsigned char*)o.c_str() , -1, -1, 0);
	if (ou != "")
	X509_NAME_add_entry_by_NID(subj,NID_organizationalUnitName, MBSTRING_ASC, 
		(unsigned char*)ou.c_str() , -1, -1, 0);
	if (email != "")
	X509_NAME_add_entry_by_NID(subj,NID_pkcs9_emailAddress, MBSTRING_ASC, 
		(unsigned char*)email.c_str() , -1, -1, 0);

	createReq(key, subj);
	X509_NAME_free(subj);
}

pki_x509req::pki_x509req(pki_x509 *cert) :pki_base()
{
	init();
	if (!cert) return;
	setDescription(cert->getDescription());
	createReq(cert->getKey(), X509_get_subject_name(cert->getCert()));
}

void pki_x509req::createReq(pki_key *key, X509_NAME *dist_name)
{
	request = X509_REQ_new();
	openssl_error();
	if (!key || key->isPubKey()) {
		openssl_error("key not valid");
		return;
	}
	openssl_error();
	X509_REQ_set_version(request, 0L);
	openssl_error();
	X509_REQ_set_pubkey(request, key->key);
	openssl_error();
	X509_REQ_get_subject_name(request) = X509_NAME_dup( dist_name);
	openssl_error();
	const EVP_MD *digest = EVP_md5();
	X509_REQ_sign(request,key->key ,digest);
	openssl_error();
	setKey(key);
}


pki_x509req::pki_x509req() : pki_base()
{
	init();
	request = X509_REQ_new();
	openssl_error();
}


pki_x509req::~pki_x509req()
{
	if (request)
		X509_REQ_free(request);
	openssl_error();
	if (privkey)
		privkey->decUcount();
}


pki_x509req::pki_x509req(const string fname)
{
	init();
	FILE *fp = fopen(fname.c_str(),"r");
	if (fp != NULL) {
	   request = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
	   if (!request) {
		ign_openssl_error();
		rewind(fp);
		CERR("Fallback to private key DER"); 
	   	request = d2i_X509_REQ_fp(fp, NULL);
		openssl_error();
	   }
	   int r = fname.rfind('.');
#ifdef WIN32	   
	   int l = fname.rfind('\\');
#else
	   int l = fname.rfind('/');
#endif
	   desc = fname.substr(l+1,r-l-1);
	   if (desc == "") desc = fname;
	   openssl_error();
	}	
	else fopen_error(fname);
	fclose(fp);
	
}

void pki_x509req::fromData(unsigned char *p, int size)
{
	privkey = NULL;
	request = d2i_X509_REQ(NULL, &p, size);
	openssl_error();
}


string pki_x509req::getDN(int nid)
{
	char buf[200] = "";
	string s;
	X509_NAME *subj = X509_REQ_get_subject_name(request);
	X509_NAME_get_text_by_NID(subj, nid, buf, 200);
	openssl_error();
	s = buf;
	return s;
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


void pki_x509req::writeReq(const string fname, bool PEM)
{
	FILE *fp = fopen(fname.c_str(),"w");
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


pki_key *pki_x509req::getKey()
{
	return privkey;
}


bool pki_x509req::setKey(pki_key *key)
{
	bool ret = false;
	if (!privkey && key) {
		CERR( "KEY COUNT UP");
		key->incUcount();
		ret=true;
	}
	privkey = key;
	return ret;
}

