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


pki_crl::pki_crl(const std::string d, pki_x509 *iss )
	:pki_base(d)
{ 
	issuer = iss;
	crl = NULL;
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
	openssl_error();
	className="pki_crl";
}	


pki_crl::~pki_crl()
{
	X509_CRL_free(crl);
}

void pki_crl::addRevoked(const pki_x509 *client)
{
	X509_REVOKED *rev = NULL;
	if (!crl) openssl_error("crl disappeared");
	X509_CRL_INFO *ci = crl->crl;
	if (!client || !client->revoked) return;
	if (client->psigner != issuer) return;
	rev = X509_REVOKED_new();
	openssl_error();
	rev->revocationDate = M_ASN1_TIME_dup(client->revoked);
	rev->serialNumber = ASN1_INTEGER_dup(X509_get_serialNumber(client->cert));
	sk_X509_REVOKED_push(ci->revoked,rev);
	openssl_error();
}

void pki_crl::addV3ext(int nid, std::string exttext)
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


void pki_crl::writeCrl(const std::string fname)
{
	FILE *fp = fopen(fname.c_str(),"w");
	if (fp != NULL) {
	   if (crl){
		CERR("writing CRL");
		PEM_write_X509_CRL(fp, crl);
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
