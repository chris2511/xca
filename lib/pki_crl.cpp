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


pki_crl::pki_crl(const string d, pki_x509 *iss )
	:pki_base(d)
{ 
	issuer = iss;
	crl = NULL;
	className="pki_crl";
	if (!iss) openssl_error("no issuer");
	crl = X509_CRL_new();
	X509V3_set_ctx(&ctx, issuer->cert, NULL, NULL, crl, 0);
	X509_CRL_INFO *ci = crl->crl;
	openssl_error();
	ci->issuer = X509_NAME_dup(issuer->cert->cert_info->subject);
	ci->lastUpdate = ASN1_UTCTIME_new();
	X509_gmtime_adj(ci->lastUpdate,0);
	ci->nextUpdate=ASN1_UTCTIME_new();
	X509_gmtime_adj(ci->nextUpdate, (issuer->getCrlDays())*24*60*60);
	ci->version = ASN1_INTEGER_new();
	ASN1_INTEGER_set(ci->version,1); /* version 2 CRL */
#if OPENSSL_VERSION_NUMBER >= 0x0090700fL	
	ci->revoked = sk_X509_REVOKED_new_null();
#endif
	openssl_error();
}	

pki_crl::pki_crl(const string fname )
	:pki_base(fname)
{ 
	issuer = NULL;
	crl = X509_CRL_new();
	className="pki_crl";
	FILE * fp = fopen(fname.c_str(), "r");
	if (fp != NULL) {
		crl = PEM_read_X509_CRL(fp, &crl, NULL, NULL);
		if (!crl) {
			ign_openssl_error();
			rewind(fp);
			CERR("Fallback to CRL - DER");
			crl = d2i_X509_CRL_fp(fp, &crl);
		}	
		fclose(fp);
		int r = fname.rfind('.');
#ifdef WIN32
		int l = fname.rfind('\\');
#else
		int l = fname.rfind('/');
#endif
		CERR( fname << "r,l: "<< r <<","<< l );
		setDescription(fname.substr(l+1,r-l-1));
		openssl_error();
	}
	else fopen_error(fname);
}

pki_crl::pki_crl()
	:pki_base()
{
	issuer = NULL;
	crl = X509_CRL_new();
	className="pki_crl";
	openssl_error();
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
	ret = X509_CRL_cmp(crl, ((pki_crl *)refcrl)->crl) == 0;
	openssl_error();
/*
	int s1,s2;
	unsigned char *p1, *p2;
	bool ret = false;
	p1 = toData(&s1);
	if (p1) {
		p2 = ((pki_crl *)refcrl)->toData(&s2);
		if (p2){
			if(s1 == s2)
				if (memcmp(p1,p2,s1) == 0)
					ret = true;
			OPENSSL_free(p2);
		}		
		OPENSSL_free(p1);
	}
*/
	return ret;
}


void pki_crl::addRevoked(pki_x509 *client)
{
	X509_REVOKED *rev = NULL;
	if (!crl) openssl_error("crl disappeared");
	X509_CRL_INFO *ci = crl->crl;
	if (!client || !client->isRevoked()) return;
	if (client->psigner != issuer) return;
	rev = X509_REVOKED_new();
	openssl_error();
	rev->revocationDate = client->getRevoked().get();
	rev->serialNumber = client->getSerial().get();
	sk_X509_REVOKED_push(ci->revoked,rev);
	openssl_error();
}

void pki_crl::addV3ext(int nid, string exttext)
{ 
	X509_EXTENSION *ext;
	int len; 
	char *c = NULL;
	if ((len = exttext.length()) == 0) return;
	len++;
	c = (char *)OPENSSL_malloc(len);
	openssl_error();
	strncpy(c, exttext.c_str(), len);
	ext =  X509V3_EXT_conf_nid(NULL, &ctx, nid, c);
	OPENSSL_free(c);
	if (!ext) {
		string x="CRL v3 Extension: " + exttext;
		openssl_error(x);
		return;
	}
	X509_CRL_add_ext(crl, ext, -1);
	X509_EXTENSION_free(ext);
	openssl_error();
}


void pki_crl::sign(pki_key *key)
{
	if (!key || key->isPubKey()) return;
	X509_CRL_sign(crl,key->key, EVP_md5());
	openssl_error();
}


void pki_crl::writeCrl(const string fname, bool pem)
{
	FILE *fp = fopen(fname.c_str(),"w");
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

ASN1_TIME *pki_crl::getDate()
{
	if (!crl || !crl->crl) return NULL;
	return crl->crl->lastUpdate;
}

int pki_crl::numRev()
{
	if (crl && crl->crl && crl->crl->revoked)
		return sk_X509_REVOKED_num(crl->crl->revoked);
	else
		return 0;
}

long pki_crl::getSerial(int num)
{
	X509_REVOKED *ret = NULL;
	long serial=-1;
	if (crl && crl->crl && crl->crl->revoked) {
		ret = sk_X509_REVOKED_value(crl->crl->revoked, num);
		serial = ASN1_INTEGER_get(ret->serialNumber);
	}
	openssl_error();
	return serial;
}	
		
ASN1_TIME *pki_crl::getRevDate(int num)
{
	X509_REVOKED *ret = NULL;
	ASN1_TIME *t = NULL;
	if (crl && crl->crl && crl->crl->revoked) {
		ret = sk_X509_REVOKED_value(crl->crl->revoked, num);
		openssl_error();
		t = M_ASN1_TIME_dup(ret->revocationDate);
	}
	return t;
}	

string pki_crl::issuerName()
{
	char *x = NULL;
	if (crl && crl->crl && crl->crl->issuer)
		x = X509_NAME_oneline(crl->crl->issuer, NULL ,0);
	string ret = x;
	if (x)
	       	OPENSSL_free(x);
	openssl_error();
	return ret;
}					  

X509_NAME *pki_crl::getIssuerX509_NAME()
{
	if (crl && crl->crl && crl->crl->issuer) {
		return crl->crl->issuer;
	}
	else 
		return NULL ;
}

bool pki_crl::verify(pki_key *key)
{
	bool ret=false;
	if (crl && crl->crl) {
		ret = X509_CRL_verify(crl , key->key) == 0;
		ign_openssl_error();
	}
	return ret ;
}	

string pki_crl::printV3ext()
{
#define V3_BUF 100
	ASN1_OBJECT *obj;
	BIO *bio = BIO_new(BIO_s_mem());
	int i, len, n = X509_CRL_get_ext_count(crl);
	char buffer[V3_BUF+1];
	X509_EXTENSION *ex;
	string text="";
	for (i=0; i<n; i++) {
		text += "<b><u>";
		ex = X509_CRL_get_ext(crl,i);
		obj = X509_EXTENSION_get_object(ex);
		len = i2t_ASN1_OBJECT(buffer, V3_BUF, obj);
		if (len <0 || len > V3_BUF) openssl_error("V3 buffer too small, this is a bug!");
		buffer[len] = '\0';
		CERR("extension: "<< buffer <<", length: " << len);
		text += buffer;
		text += ": ";
		if (X509_EXTENSION_get_critical(ex)) {
			text += " <font color=\"red\">critical</font>:";
		}
		if(!X509V3_EXT_print(bio, ex, 0, 0)) {
			M_ASN1_OCTET_STRING_print(bio,ex->value);
		}
		text+="</u></b><br><tt>";
        	do {
			len = BIO_read(bio, buffer, V3_BUF);
			buffer[len] = '\0';
			text+=buffer;
			CERR("extension-length: "<< len);
		} while (len == V3_BUF);
		text+="</tt><br>";
	}
	BIO_free(bio);
	openssl_error();
	return text;
}
