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
#include "exception.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <string.h>

QPixmap *pki_x509req::icon[3] = { NULL, NULL, NULL };

pki_x509req::pki_x509req()
	: pki_x509super()
{
	privkey = NULL;
	class_name = "pki_x509req";
	request = X509_REQ_new();
	openssl_error();
	spki = NULL;
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
	class_name = "pki_x509req";
	request = NULL;
	spki = NULL;

	// request file section
	FILE *fp = fopen(fname.latin1(),"r");
	if (fp != NULL) {
		request = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
		// if der format
		if (!request) {
			ign_openssl_error();
			rewind(fp);
			request = d2i_X509_REQ_fp(fp, NULL);
		}
		// SPKAC
		if (!request) {
			ign_openssl_error();
			rewind(fp);
			load_spkac(fname);
			openssl_error();
		}
	}else
		fopen_error(fname);
	fclose(fp);

	autoIntName();
	if (getIntName().isEmpty())
		setIntName(rmslashdot(fname));
	openssl_error();
}

void pki_x509req::fromData(unsigned char *p, int size)
{
	unsigned char *ps = p;
	privkey = NULL;
	request = d2i_X509_REQ(&request, &ps, size);
	printf("SPKAC %p - %p = %d <-> %d\n",ps, p, ps - p, size);
	if (ps - p < size)
		spki = d2i_NETSCAPE_SPKI(NULL, &ps , size + p - ps); 
	openssl_error();
}

x509name pki_x509req::getSubject() const
{
	x509name x(X509_REQ_get_subject_name(request));
	openssl_error();
	return x;
}

bool pki_x509req::isSpki() const
{
	return spki != NULL;
}

unsigned char *pki_x509req::toData(int *size)
{
	unsigned char *p, *p1;
	*size = i2d_X509_REQ(request, NULL);
	if (spki) {
		*size += i2d_NETSCAPE_SPKI(spki, NULL);
	}
	openssl_error();
	p = (unsigned char*)OPENSSL_malloc(*size);
	p1 = p;
	i2d_X509_REQ(request, &p1);
	if (spki) {
		printf("Writing SPKAC");
		i2d_NETSCAPE_SPKI(spki, &p1);
	}
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
	 bool x = (X509_REQ_verify(request,pkey) >= 0);
	 printf("x: %d, spki: %p\n",x, spki);
	 if ( !x  && spki != NULL) {
		printf("SPKAC\n");
 		ign_openssl_error();
		x = NETSCAPE_SPKI_verify(spki, pkey) >= 0;
	 }
	 EVP_PKEY_free(pkey);
	 openssl_error();
	 return x;
}

pki_key *pki_x509req::getPubKey() const
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
	if (getRefKey() != NULL ) pixnum = 1;
	if (spki != NULL) pixnum = 2;
	pointer->setPixmap(0, *icon[pixnum]);
	pointer->setText(1, getSubject().getEntryByNid(NID_commonName));
}

QString pki_x509req::getSigAlg()
{
	QString alg = OBJ_nid2ln(OBJ_obj2nid(request->sig_alg->algorithm));
	return alg;
}

int pki_x509req::fix_data(int nid, int *type)
	{
	if (nid == NID_pkcs9_emailAddress)
		*type=V_ASN1_IA5STRING;
	if ((nid == NID_commonName) && (*type == V_ASN1_IA5STRING))
		*type=V_ASN1_T61STRING;
	if ((nid == NID_pkcs9_challengePassword) && (*type == V_ASN1_IA5STRING))
		*type=V_ASN1_T61STRING;
	if ((nid == NID_pkcs9_unstructuredName) && (*type == V_ASN1_T61STRING))
		return(0);
	if (nid == NID_pkcs9_unstructuredName)
		*type=V_ASN1_IA5STRING;
	return(1);
	}

	/**
* function for making a x509 request out of a spkac netscape request.
* The spkac file is parsed and the information assembled to the x509 format
*/

void pki_x509req::load_spkac(const QString filename)
{

	STACK_OF(CONF_VALUE) *sk=NULL;
	LHASH *parms=NULL;
	CONF_VALUE *cv=NULL;
	X509_REQ_INFO *ri;
	char *type,*buf;
	EVP_PKEY *pktmp=NULL;
	X509_NAME *n=NULL;
	X509_NAME_ENTRY *ne=NULL;
	int i,j;
	long errline;
	int nid;
	QString eerror;

	parms=CONF_load(NULL,filename,&errline);
	if (parms == NULL)
		{
		eerror.sprintf("error on line %ld", errline);
		goto err;
		}

	sk=CONF_get_section(parms, "default");
	if (sk_CONF_VALUE_num(sk) == 0)
		{
		eerror = "no name/value pairs found";
		goto err;
		}
	/*
	 * Create the request structure, parsing the spkac file
	*/

	request = X509_REQ_new();
	openssl_error();
	
	/*
	 * Build up the subject name set.
	 */
	ri=request->req_info;
	n = ri->subject;

	for (i = 0; ; i++)
		{
		if (sk_CONF_VALUE_num(sk) <= i) break;

		cv=sk_CONF_VALUE_value(sk,i);
		type=cv->name;
		/* Skip past any leading X. X: X, etc to allow for
		 * multiple instances
		 */
		for (buf = cv->name; *buf ; buf++)
			if ((*buf == ':') || (*buf == ',') || (*buf == '.'))
				{
				buf++;
				if (*buf) type = buf;
				break;
				}

		buf=cv->value;
		if ((nid=OBJ_txt2nid(type)) == NID_undef)
			{
			if (strcmp(type, "SPKAC") == 0)
				{
				spki = NETSCAPE_SPKI_b64_decode(cv->value, -1);
				if (spki == NULL)
					{
					eerror = "unable to load Netscape SPKAC structure";
					goto err;
					}
				}
			continue;
			}

		j=ASN1_PRINTABLE_type((unsigned char *)buf,-1);
		if (fix_data(nid, &j) == 0)
			{
			eerror.sprintf("invalid characters in string %s",buf);
			goto err;
			}

		if ((ne=X509_NAME_ENTRY_create_by_NID(&ne,nid,j,(unsigned char *)buf,strlen(buf))) == NULL)
			{
			eerror.sprintf("failed to create Name entry %s",buf);
			goto err;
			}

		if (!X509_NAME_add_entry(n,ne,-1, 0)) 
			{
			eerror.sprintf("failed to add Name entry %s",buf);
			goto err;
			}
		}
	if (spki == NULL)
		{
		eerror = "Netscape SPKAC structure not found";
		goto err;
		}

	/*
	 * Now extract the key from the SPKI structure.
	 */

	if ((pktmp=NETSCAPE_SPKI_get_pubkey(spki)) == NULL)
		{
		eerror = "error unpacking SPKAC public key";
		goto err;
		}

	j = NETSCAPE_SPKI_verify(spki, pktmp);
	if (j <= 0)
		{
		eerror = "signature verification failed on SPKAC public key";
		goto err;
		}

	X509_REQ_set_pubkey(request,pktmp);
	EVP_PKEY_free(pktmp);
    return;
err:
	if (request != NULL){
		 X509_REQ_free(request);
		 request=NULL;
	}
	if (parms != NULL) CONF_free(parms);
	if (spki != NULL) {
		NETSCAPE_SPKI_free(spki);
		spki = NULL;
	}
	if (ne != NULL) X509_NAME_ENTRY_free(ne);
	openssl_error(QString::fromLatin1("SPKAC Error: ") + eerror + "(" + filename +")" );

}
