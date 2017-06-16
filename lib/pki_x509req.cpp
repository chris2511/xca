/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
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
#include <QDir>

QPixmap *pki_x509req::icon[4] = { NULL, NULL, NULL, NULL };

pki_x509req::pki_x509req(const QString name)
	: pki_x509super(name)
{
	privkey = NULL;
	class_name = "pki_x509req";
	request = X509_REQ_new();
	pki_openssl_error();
	spki = NULL;
	dataVersion=1;
	pkiType=x509_req;
	done = false;
}

pki_x509req::~pki_x509req()
{
	if (request)
		X509_REQ_free(request);
	if (spki)
		NETSCAPE_SPKI_free(spki);
	pki_openssl_error();
}

void pki_x509req::createReq(pki_key *key, const x509name &dn, const EVP_MD *md, extList el)
{
	int bad_nids[] = { NID_subject_key_identifier, NID_authority_key_identifier,
		NID_issuer_alt_name, NID_undef };

	EVP_PKEY *privkey = NULL;

	if (key->isPubKey()) {
		my_error(tr("Signing key not valid (public key)"));
		return;
	}

	X509_REQ_set_version(request, 0L);
	X509_REQ_set_pubkey(request, key->getPubKey());
	setSubject(dn);
	pki_openssl_error();

	for(int i=0; bad_nids[i] != NID_undef; i++)
		el.delByNid(bad_nids[i]);

	el.delInvalid();

	if (el.count() > 0) {
		STACK_OF(X509_EXTENSION) *sk;
		sk = el.getStack();
		X509_REQ_add_extensions(request, sk);
		sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	}
	pki_openssl_error();

	privkey = key->decryptKey();
	X509_REQ_sign(request, privkey, md);
	pki_openssl_error();
	EVP_PKEY_free(privkey);
}

QString pki_x509req::getMsg(msg_type msg)
{
	/*
	 * We do not construct english sentences from fragments
	 * to allow proper translations.
	 * The drawback are all the slightly different duplicated messages
	 *
	 * %1 will be replaced by either "SPKAC" or "PKCS#10"
	 * %2 will be replaced by the internal name of the request
	 */

	QString type = isSpki() ? "SPKAC" : "PKCS#10";

	switch (msg) {
	case msg_import: return tr("Successfully imported the %1 certificate request '%2'").arg(type);
	case msg_delete: return tr("Delete the %1 certificate request '%2'?").arg(type);
	case msg_create: return tr("Successfully created the %1 certificate request '%2'").arg(type);
	/* %1: Number of requests; %2: list of request names */
	case msg_delete_multi: return tr("Delete the %1 certificate requests: %2?");
	}
	return pki_base::getMsg(msg);
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
	FILE *fp = fopen_read(fname);
	X509_REQ *_req;
	int ret = 0;

	if (fp != NULL) {
		_req = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
		if (!_req) {
			pki_ign_openssl_error();
			rewind(fp);
			_req = d2i_X509_REQ_fp(fp, NULL);
		}
		fclose(fp);
		// SPKAC
		if (!_req) {
			pki_ign_openssl_error();
			ret = load_spkac(fname);
		}
		if (ret || pki_ign_openssl_error()) {
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
	int size;

	size = head->len - sizeof(db_header_t);

	oldFromData((unsigned char *)p, size);
}

void pki_x509req::addAttribute(int nid, QString content)
{
	if (content.isEmpty())
		return;

	ASN1_STRING *a = QStringToAsn1(content, nid);
	X509_REQ_add1_attr_by_NID(request, nid, a->type, a->data, a->length);
	ASN1_STRING_free(a);
	openssl_error(QString("'%1' (%2)").arg(content).arg(OBJ_nid2ln(nid)));
}

x509name pki_x509req::getSubject() const
{
	x509name x(X509_REQ_get_subject_name(request));
	pki_openssl_error();
	return x;
}

const ASN1_OBJECT *pki_x509req::sigAlg()
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	const ASN1_BIT_STRING *psig;
	const X509_ALGOR *palg;
	const ASN1_OBJECT *paobj;
	int pptype;
	const void *ppval;

	X509_REQ_get0_signature(request, &psig, &palg);
	X509_ALGOR_get0(&paobj, &pptype, &ppval, palg);
	return paobj;
#else
	return request->sig_alg->algorithm;
#endif
}

void pki_x509req::setSubject(const x509name &n)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	X509_REQ_set_subject_name(request, n.get());
#else
	if (request->req_info->subject != NULL)
		X509_NAME_free(request->req_info->subject);
	request->req_info->subject = n.get();
#endif
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
	pki_openssl_error();
	return ba;
}
void pki_x509req::writeDefault(const QString fname)
{
	writeReq(fname + QDir::separator() + getIntName() + ".csr", true);
}

void pki_x509req::writeReq(const QString fname, bool pem)
{
	FILE *fp = fopen_write(fname);
	if (fp) {
		if (request){
			if (pem)
				PEM_write_X509_REQ(fp, request);
			else
				i2d_X509_REQ_fp(fp, request);
		}
		fclose(fp);
		pki_openssl_error();
	} else
		fopen_error(fname);
}

BIO *pki_x509req::pem(BIO *b, int format)
{
	(void)format;
	if (!b)
		b = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(b, request);
	return b;
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
	pki_ign_openssl_error();
	EVP_PKEY_free(pkey);
	return x;
}

pki_key *pki_x509req::getPubKey() const
{
	 EVP_PKEY *pkey = X509_REQ_get_pubkey(request);
	 pki_ign_openssl_error();
	 if (pkey == NULL)
		 return NULL;
	 pki_evp *key = new pki_evp(pkey);
	 pki_openssl_error();
	 return key;
}

QString pki_x509req::getSigAlg()
{
	const ASN1_OBJECT *o;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	const ASN1_BIT_STRING *psig;
	const X509_ALGOR *palg;
	X509_ALGOR *palg2;
	int pptype;
	const void *ppval;

	if (spki) {
		X509_PUBKEY_get0_param(NULL, NULL, NULL, &palg2, spki->spkac->pubkey);
		palg = palg2;
	} else
		X509_REQ_get0_signature(request, &psig, &palg);
	X509_ALGOR_get0(&o, &pptype, &ppval, palg);
#else
	if (spki) {
		o = spki->spkac->pubkey->algor->algorithm;
	} else {
		o = request->sig_alg->algorithm;
	}
#endif
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
	pki_ign_openssl_error();

	file.setFileName(filename);
        if (!file.open(QIODevice::ReadOnly))
		return 1;

	while (!file.atEnd()) {
		int idx, nid;
		QByteArray line = file.readLine();
		if (line.size() == 0)
			continue;
		idx = line.indexOf('=');
		if (idx == -1)
			goto err;
		QString type = line.left(idx).trimmed();
		line = line.mid(idx+1).trimmed();

		idx = type.lastIndexOf(QRegExp("[:,\\.]"));
		if (idx != -1)
			type = type.mid(idx+1);

		if ((nid = OBJ_txt2nid(CCHAR(type))) == NID_undef) {
			if (type != "SPKAC")
				goto err;
			pki_ign_openssl_error();
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

QString pki_x509req::getAttribute(int nid)
{
	int n;
	int count;
	QStringList ret;

	n = X509_REQ_get_attr_by_NID(request, nid, -1);
	if (n == -1)
		return QString("");
	X509_ATTRIBUTE *att = X509_REQ_get_attr(request, n);
	if (!att)
		return QString("");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	count = X509_ATTRIBUTE_count(att);
	for (int j = 0; j < count; j++)
		ret << asn1ToQString(X509_ATTRIBUTE_get0_type(att, j)->
				             value.asn1_string);
#else
	if (att->single)
		return asn1ToQString(att->value.single->value.asn1_string);

	count = sk_ASN1_TYPE_num(att->value.set);
	for (int j=0; j<count; j++) {
		ret << asn1ToQString(sk_ASN1_TYPE_value(att->value.set, j)->
					value.asn1_string);
	}
#endif
	return ret.join(", ");
}

QVariant pki_x509req::column_data(dbheader *hd)
{
	switch (hd->id) {
	case HD_req_signed:
		return QVariant(done ? tr("Signed") : tr("Unhandled"));
	case HD_req_unstr_name:
		return getAttribute(NID_pkcs9_unstructuredName);
	case HD_req_chall_pass:
		return getAttribute(NID_pkcs9_challengePassword);
	}
	return pki_x509super::column_data(hd);
}

QVariant pki_x509req::getIcon(dbheader *hd)
{
	int pixnum = -1;
	pki_key *k;

	switch (hd->id) {
	case HD_internal_name:
		pixnum = 0;
		k = getRefKey();
		if (k && k->isPrivKey())
			pixnum = 1;
		if (spki != NULL)
			 pixnum = 2;
		break;
	case HD_req_signed:
		if (done)
			pixnum = 3;
		break;
	}
	if (pixnum == -1)
		return QVariant();
	return QVariant(*icon[pixnum]);
}

bool pki_x509req::visible()
{
	if (pki_x509super::visible())
		return true;
	if (getAttribute(NID_pkcs9_unstructuredName).contains(limitPattern))
		return true;
	if (getAttribute(NID_pkcs9_challengePassword).contains(limitPattern))
		return true;
	return false;
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

