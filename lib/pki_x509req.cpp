/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */



#include "pki_x509.h"
#include "pki_evp.h"
#include "func.h"
#include "x509name.h"
#include "exception.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <qdir.h>

QPixmap *pki_x509req::icon[4] = { NULL, NULL, NULL, NULL };

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
	cols=3;
	done = false;
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

QString pki_x509req::getFriendlyClassName()
{
	return isSpki() ? tr("SPKAC request") : tr("PKCS#10 request");
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
	FILE *fp = fopen(QString2filename(fname), "r");
	X509_REQ *_req;
	int ret = 0;

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
			ret = load_spkac(fname);
		}
		fclose(fp);
		if (ret || ign_openssl_error()) {
			if (_req)
				X509_REQ_free(_req);
			throw errorEx(tr("Unable to load the certificate request in file %1. Tried PEM, DER and SPKAC format.").arg(fname));
		}
	} else {
		fopen_error(fname);
		return;
	}

	if (_req) {
		X509_REQ_free(request);
		request = _req;
	}
	autoIntName();
	if (getIntName().isEmpty())
		setIntName(rmslashdot(fname));
	openssl_error(fname);
}

void pki_x509req::d2i(QByteArray &ba)
{
	X509_REQ *r= (X509_REQ*)d2i_bytearray(D2I_VOID(d2i_X509_REQ), ba);
	if (r) {
		X509_REQ_free(request);
		request = r;
	}
}

void pki_x509req::d2i_spki(QByteArray &ba)
{
	NETSCAPE_SPKI *s = (NETSCAPE_SPKI*)d2i_bytearray(
				D2I_VOID(d2i_NETSCAPE_SPKI), ba);
        if (s) {
		NETSCAPE_SPKI_free(spki);
		spki = s;
	}
}

QByteArray pki_x509req::i2d()
{
	return i2d_bytearray(I2D_VOID(i2d_X509_REQ), request);
}

QByteArray pki_x509req::i2d_spki()
{
	return i2d_bytearray(I2D_VOID(i2d_NETSCAPE_SPKI), spki);
}

void pki_x509req::fromData(const unsigned char *p, db_header_t *head )
{
	int version, size;

	size = head->len - sizeof(db_header_t);
	version = head->version;

	oldFromData((unsigned char *)p, size);
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

QByteArray pki_x509req::toData()
{
	QByteArray ba;

	ba += i2d();
	if (spki) {
		ba += i2d_spki();
	}
	openssl_error();
	return ba;
}
void pki_x509req::writeDefault(const QString fname)
{
	writeReq(fname + QDir::separator() + getIntName() + ".csr", true);
}

void pki_x509req::writeReq(const QString fname, bool pem)
{
	FILE *fp = fopen(QString2filename(fname), "w");
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
	const EVP_MD *digest=EVP_md5();
	unsigned char d1[EVP_MAX_MD_SIZE], d2[EVP_MAX_MD_SIZE];
	unsigned int d1_len,d2_len;

	if (!refreq)
		 return false;
	X509_REQ_digest(request, digest, d1, &d1_len);
	X509_REQ_digest(((pki_x509req *)refreq)->request, digest, d2, &d2_len);
	ign_openssl_error();
	if ((d1_len == d2_len) &&
	    (d1_len >0) &&
	    (memcmp(d1,d2,d1_len) == 0) )
	{
		return true;
	}
	return false;
}

int pki_x509req::verify()
{
	EVP_PKEY *pkey = X509_REQ_get_pubkey(request);
	bool x;

	if (spki) {
		x = NETSCAPE_SPKI_verify(spki, pkey) > 0;
	} else {
		x = X509_REQ_verify(request,pkey) > 0;
	}
	ign_openssl_error();
	EVP_PKEY_free(pkey);
	return x;
}

pki_key *pki_x509req::getPubKey() const
{
	 EVP_PKEY *pkey = X509_REQ_get_pubkey(request);
	 ign_openssl_error();
	 if (pkey == NULL)
		 return NULL;
	 pki_evp *key = new pki_evp(pkey);
	 openssl_error();
	 return key;
}

QString pki_x509req::getSigAlg()
{
	ASN1_OBJECT *o;
	if (spki) {
		o = spki->spkac->pubkey->algor->algorithm;
	} else {
		o = request->sig_alg->algorithm;
	}
	return QString(OBJ_nid2ln(OBJ_obj2nid(o)));
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
   Load a spkac FILE into this request structure.
   The file format follows the conventions understood by the 'openssl ca'
   command. (see: 'man ca')
*/
int pki_x509req::load_spkac(const QString filename)
{
	QFile file;
	x509name subject;
	EVP_PKEY *pktmp = NULL;
	ign_openssl_error();

	file.setFileName(filename);
        if (!file.open(QIODevice::ReadWrite))
		return 1;

	while (!file.atEnd()) {
		int idx, nid;
		QByteArray line = file.readLine().trimmed();
		if (line.size() == 0)
			continue;
		idx = line.indexOf('=');
		if (idx == -1)
			goto err;
		QString type = line.left(idx);
		line = line.mid(idx+1);

		idx = type.lastIndexOf(QRegExp("[:,\\.]"));
		if (idx != -1)
			type = type.mid(idx+1);

		if ((nid = OBJ_txt2nid(CCHAR(type))) == NID_undef) {
			if (type != "SPKAC")
				goto err;
			ign_openssl_error();
			spki = NETSCAPE_SPKI_b64_decode(line, line.size());
			if (!spki)
				goto err;
			/*
			  Now extract the key from the SPKI structure and
			  check the signature.
			 */
			pktmp = NETSCAPE_SPKI_get_pubkey(spki);
			if (pktmp == NULL)
				goto err;

			if (NETSCAPE_SPKI_verify(spki, pktmp) != 1)
				goto err;
		} else {
			// gather all values in the x509name subject.
			subject.addEntryByNid(nid,
				filename2QString(line.constData()));
		}
	}
	if (!pktmp)
		goto err;
	setSubject(subject);
	X509_REQ_set_pubkey(request, pktmp);
	EVP_PKEY_free(pktmp);
	return 0;
err:
	if (pktmp)
		EVP_PKEY_free(pktmp);
	if (spki) {
		NETSCAPE_SPKI_free(spki);
		spki = NULL;
	}
	return 1;
}

ASN1_IA5STRING *pki_x509req::spki_challange()
{
	if (spki) {
		if (spki->spkac->challenge->length >0)
			return spki->spkac->challenge;
	}
	return NULL;
}

QVariant pki_x509req::column_data(int col)
{
	switch (col) {
		case 0:
			return QVariant(getIntName());
		case 1:
			return QVariant(getSubject().getEntryByNid(NID_commonName));
		case 2:
			return QVariant(done ? tr("Signed") : tr("Unhandled"));
	}
	return QVariant();
}
QVariant pki_x509req::getIcon(int column)
{
	int pixnum = -1;

	switch (column) {
	case 0:
		pixnum = 0;
		if (getRefKey() != NULL )
			pixnum = 1;
		if (spki != NULL)
			 pixnum = 2;
		break;
	case 2:
		if (done)
			pixnum = 3;
		break;
	}
	if (pixnum == -1)
		return QVariant();
	return QVariant(*icon[pixnum]);
}

void pki_x509req::oldFromData(unsigned char *p, int size)
{
	QByteArray ba((const char *)p, size);
	privkey = NULL;

	d2i(ba);
	if (ba.count() > 0)
		d2i_spki(ba);

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}

