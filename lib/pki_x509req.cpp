/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
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
	dataVersion=1;
	pkiType=x509_req;
	cols=2;
}

pki_x509req::~pki_x509req()
{
	if (request)
		X509_REQ_free(request);
	if (spki)
		NETSCAPE_SPKI_free(spki);
	openssl_error();
}

void pki_x509req::createReq(pki_key *key, const x509name &dn, const EVP_MD *md, extList el)
{
	int bad_nids[] = { NID_subject_key_identifier, NID_authority_key_identifier,
		NID_issuer_alt_name, NID_undef };

	EVP_PKEY *privkey = NULL;
	STACK_OF(X509_EXTENSION) *sk;

	if (key->isPubKey()) {
		my_error(tr("Signing key not valid (public key)"));
		return;
	}

	X509_REQ_set_version(request, 0L);
	X509_REQ_set_pubkey(request, key->getPubKey());
	setSubject(dn);
	openssl_error();

	for(int i=0; bad_nids[i] != NID_undef; i++)
		el.delByNid(bad_nids[i]);

	el.delInvalid();

	sk = el.getStack();
	X509_REQ_add_extensions(request, sk);
	sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	openssl_error();

	privkey = key->decryptKey();
	X509_REQ_sign(request, privkey, md);
	openssl_error();
	EVP_PKEY_free(privkey);
}


void pki_x509req::fromPEM_BIO(BIO *bio, QString name)
{
	X509_REQ *req;
	req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	openssl_error(name);
	X509_REQ_free(request);
	request = req;
	autoIntName();
	if (getIntName().isEmpty())
		setIntName(rmslashdot(name));
}

void pki_x509req::fload(const QString fname)
{
	FILE *fp = fopen(CCHAR(fname), "r");
	X509_REQ *_req;
	if (fp != NULL) {
		_req = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
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
		}
		fclose(fp);
		openssl_error(fname);
	} else {
		fopen_error(fname);
		return;
	}

	if( _req ) {
		X509_REQ_free(request);
		request = _req;
	}
	autoIntName();
	if (getIntName().isEmpty())
		setIntName(rmslashdot(fname));
	openssl_error(fname);
}

void pki_x509req::fromData(const unsigned char *p, db_header_t *head )
{
	const unsigned char *ps = p;
	int version, size;

	size = head->len - sizeof(db_header_t);
	version = head->version;

	privkey = NULL;
	request = D2I_CLASH(d2i_X509_REQ, &request, &ps, size);
	openssl_error();
	if (ps - p < size)
		spki = D2I_CLASH(d2i_NETSCAPE_SPKI, NULL, &ps , size + p - ps);
	openssl_error();
}

void pki_x509req::addAttribute(int nid, QString content)
{
	if (content.isEmpty())
		return;

	ASN1_STRING *a = QStringToAsn1(content, nid);
	if (!a) {
		openssl_error();
		return;
	}
	X509_REQ_add1_attr_by_NID(request, nid, a->type, a->data, a->length);
	ASN1_STRING_free(a);
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
	writeReq(fname + QDir::separator() + getIntName() + ".csr", true);
}

void pki_x509req::writeReq(const QString fname, bool pem)
{
	FILE *fp = fopen(CCHAR(fname), "w");
	if (fp) {
		if (request){
			if (pem)
				PEM_write_X509_REQ(fp, request);
			else
				i2d_X509_REQ_fp(fp, request);
		}
		fclose(fp);
		openssl_error();
	} else
		fopen_error(fname);
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
	if (x) {
		ign_openssl_error();
	}
	EVP_PKEY_free(pkey);
	try {
		openssl_error();
	}
	catch (errorEx &err) {
		if (!err.isEmpty())
			printf("Error: %s\n", CCHAR(err.getString()));
	}
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

QString pki_x509req::getSigAlg()
{
	QString alg = OBJ_nid2ln(OBJ_obj2nid(request->sig_alg->algorithm));
	return alg;
}

extList pki_x509req::getV3ext()
{
	extList el;
	STACK_OF(X509_EXTENSION) *sk;
	sk = X509_REQ_get_extensions(request);
	el.setStack(sk);
	sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	return el;
}

/*!
   Sets the public key of this request to the public key of the
   DER-encoded Netscape SPKI structure contained in the supplied
   raw data array.
*/
void pki_x509req::setSPKIFromData(const unsigned char *p, int size)
{
	NETSCAPE_SPKI *spki = D2I_CLASH(d2i_NETSCAPE_SPKI, NULL, &p, size);
	if (spki)
		set_spki (spki);
	openssl_error();
}

/*!
   Sets the public key of this request to the public key of the
   base64-encoded Netscape SPKI structure contained in the supplied
   null-terminated string.
*/
void pki_x509req::setSPKIBase64(const char *p)
{
	NETSCAPE_SPKI *spki = NETSCAPE_SPKI_b64_decode(p, -1);
	if (spki)
		set_spki (spki);
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
	openssl_error();
	pktmp=NETSCAPE_SPKI_get_pubkey(_spki);
	if (pktmp == NULL)
		goto err;

	if (NETSCAPE_SPKI_verify(_spki, pktmp) <= 0)
		goto err;

	X509_REQ_set_pubkey(request, pktmp);

	// replace the internally stored spki structure.
	if (spki)
		NETSCAPE_SPKI_free(spki);
	spki=_spki;
	openssl_error();
	return;
 err:
	NETSCAPE_SPKI_free(_spki);
	if (pktmp != NULL)
		EVP_PKEY_free(pktmp);
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
		parms = CONF_load(NULL, CCHAR(filename),&errline);
		if (parms == NULL)
			my_error(QString("error on line %1 of %2\n")
				      .arg(errline).arg(filename));

		sk=CONF_get_section(parms, "default");
		if (sk_CONF_VALUE_num(sk) == 0)
			my_error(tr("no key/value pairs found in %1\n").arg(filename));

		/*
		 * Build up the subject name set.
		 */
		for (i = 0; ; i++) {
			if (sk_CONF_VALUE_num(sk) <= i)
				break;
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
				ign_openssl_error();
				// ... or a SPKAC tag.
				if (strcmp(type, "SPKAC") == 0)
					setSPKIBase64(cv->value);
				else
					// ... or throw an error.
					my_error(tr("Unknown name tag %1 found in %2\n")
							.arg(type).arg(filename));

				spki_found=true;
				}
			else
				// gather all values in the x509name subject.
				subject.addEntryByNid(nid,cv->value);
		}
		if (!spki_found)
			my_error(tr("No Netscape SPKAC structure found in %1\n").arg(filename));

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

QVariant pki_x509req::column_data(int col)
{
	switch (col) {
		case 0:
			return QVariant(getIntName());
		case 1:
			return QVariant(getSubject().getEntryByNid(NID_commonName));
	}
	return QVariant();
}
QVariant pki_x509req::getIcon()
{
	int pixnum = 0;
	if (getRefKey() != NULL ) pixnum = 1;
	if (spki != NULL) pixnum = 2;
	return QVariant(*icon[pixnum]);
}

void pki_x509req::oldFromData(unsigned char *p, int size)
{
	const unsigned char *ps = p;
	privkey = NULL;
	request = D2I_CLASH(d2i_X509_REQ, &request, &ps, size);
	if (ps - p < size)
		spki = D2I_CLASH(d2i_NETSCAPE_SPKI, NULL, &ps , size + p - ps);
	openssl_error();
}

