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
#include <qdir.h>

QPixmap *pki_x509req::icon[3] = { NULL, NULL, NULL };

pki_x509req::pki_x509req(const QString name)
	: pki_x509super(name)
{
	privkey = NULL;
	class_name = "pki_x509req";
	request = X509_REQ_new();
	openssl_error();
	spki = NULL;
}

pki_x509req::~pki_x509req()
{
	if (request)
		X509_REQ_free(request);
	if (spki)
		NETSCAPE_SPKI_free(spki);
	openssl_error();
}

void pki_x509req::createReq(pki_key *key, const x509name &dn, const EVP_MD *md)
{
	EVP_PKEY *privkey = NULL;
	if (key->isPubKey()) {
		openssl_error("key not valid");
		return;
	}
	openssl_error();
	X509_REQ_set_version(request, 0L);
	X509_REQ_set_pubkey(request, key->getKey());
	setSubject(dn);
	openssl_error();
	privkey = key->decryptKey();
	X509_REQ_sign(request, privkey, md);
	openssl_error();
	EVP_PKEY_free(privkey);
}

void pki_x509req::fload(const QString fname)
{
	// request file section
	FILE *fp = fopen(fname.latin1(),"r");
	X509_REQ *_req;
	if (fp != NULL) {
		_req = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
		// if DER format
		if (!_req) {
			ign_openssl_error();
			rewind(fp);
			_req = d2i_X509_REQ_fp(fp, NULL);
		}
		// SPKAC
		if (!_req) {
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
	
	if( _req ) {
		X509_REQ_free(request);
		request = _req;
	}
}

void pki_x509req::fromData(const unsigned char *p, int size)
{
	const unsigned char *ps = p;
	privkey = NULL;
	request = D2I_CLASH(d2i_X509_REQ, &request, &ps, size);
	if (ps - p < size)
		spki = D2I_CLASH(d2i_NETSCAPE_SPKI, NULL, &ps , size + p - ps); 
	openssl_error();
}

x509name pki_x509req::getSubject() const
{
	x509name x(X509_REQ_get_subject_name(request));
	openssl_error();
	return x;
}

void pki_x509req::setSubject(const x509name &n)
{
	if (request->req_info->subject != NULL)
		X509_NAME_free(request->req_info->subject);
	request->req_info->subject = n.get();
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
		i2d_NETSCAPE_SPKI(spki, &p1);
	}
	openssl_error();
	return p;
}
void pki_x509req::writeDefault(const QString fname)
{
	writeReq(fname + QDir::separator() + getIntName() + ".req", true);
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
	if ( !x  && spki != NULL) {
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
	 ign_openssl_error();
	 if (pkey == NULL) return NULL;
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

/*!
   Sets the public key of this request to the public key of the
   DER-encoded Netscape SPKI structure contained in the supplied
   raw data array.
*/
void pki_x509req::setSPKIFromData(const unsigned char *p, int size)
{
	NETSCAPE_SPKI *spki = NULL;

	spki = D2I_CLASH(d2i_NETSCAPE_SPKI, NULL, &p, size);
	if (spki == NULL) goto err;

	set_spki (spki);
 err:
	openssl_error();
}

/*!
   Sets the public key of this request to the public key of the
   base64-encoded Netscape SPKI structure contained in the supplied
   null-terminated string.
*/
void pki_x509req::setSPKIBase64(const char *p)
{
	NETSCAPE_SPKI *spki = NULL;

	spki = NETSCAPE_SPKI_b64_decode(p, -1);
	if (spki == NULL) goto err;

	set_spki (spki);
 err:
	openssl_error();
}

/*!
   Sets the public key of this request to the public key of the
   given Netscape SPKI structure. Throws an error exception, if the
   verification of the signature contained in the SPKI structure fails.
   The SPKI structure is implicitly freed by this internal function upon
   error. On success, the internally stored SPKI structure is replaced.
*/
void pki_x509req::set_spki(NETSCAPE_SPKI *_spki)
{
	EVP_PKEY *pktmp=NULL;

	/*
	  Now extract the key from the SPKI structure and
	   check the signature.
	 */

	pktmp=NETSCAPE_SPKI_get_pubkey(_spki);
	if (pktmp == NULL) goto err;

	if (NETSCAPE_SPKI_verify(_spki, pktmp) <= 0) goto err;
		
	X509_REQ_set_pubkey(request,pktmp);

	// replace the internally stored spki structure.
	if (spki)
		NETSCAPE_SPKI_free(spki);
	spki=_spki;
	return;
 err:
	NETSCAPE_SPKI_free(_spki);
	if (pktmp != NULL) EVP_PKEY_free(pktmp);
	openssl_error();
}

/*!
   Load a spkac FILE into this request structure. 
   The file format follows the conventions understood by the 'openssl ca'
   command. (see: 'man ca')

   Indeed, this function is derived from the original sources in  ca.c
   of the openssl package.
*/

void pki_x509req::load_spkac(const QString filename)
{
	STACK_OF(CONF_VALUE) *sk=NULL;
	LHASH *parms=NULL;
	CONF_VALUE *cv=NULL;
	x509name subject;
	char *type,*buf;
	int i;
	long errline;
	int nid;
	bool spki_found =false;

	try { // be aware of any exceptions
		parms=CONF_load(NULL,filename.latin1(),&errline);
		if (parms == NULL)
			openssl_error(QString("error on line %1 of %2\n")
				      .arg(errline).arg(filename));

		sk=CONF_get_section(parms, "default");
		if (sk_CONF_VALUE_num(sk) == 0)
			openssl_error(QString("no name/value pairs found in %1\n").arg(filename));

		/*
		 * Build up the subject name set.
		 */
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
			// check for a valid DN component.
			if ((nid=OBJ_txt2nid(type)) == NID_undef)
				{
				// ... or a SPKAC tag. 
				if (strcmp(type, "SPKAC") == 0)
					setSPKIBase64(cv->value);
				else
				  // ... or throw an error.
					openssl_error(QString("Unknown name tag %1 found in %2\n").arg(type).arg(filename));

				spki_found=true;
				}
			else
				// gather all values in the x509name subject.
				subject.addEntryByNid(nid,cv->value);
			}
		if (!spki_found)
			openssl_error(QString("No Netscape SPKAC structure found in %1\n").arg(filename));

		/*
		 * Now set the subject.
		 */
		setSubject(subject);
		if (parms != NULL) CONF_free(parms);
		}
	catch (errorEx &e)
		{
		// clean up the request pointer
		if (spki){
			NETSCAPE_SPKI_free(spki);
			spki=NULL;
		}
		if (parms != NULL) CONF_free(parms);
		throw e;
		}
}
