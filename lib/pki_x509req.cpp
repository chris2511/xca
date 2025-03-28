/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include <typeinfo>

#include "pki_x509.h"
#include "pki_x509req.h"
#include "pki_evp.h"
#include "func.h"
#include "db_base.h"
#include "x509name.h"
#include "exception.h"
#include <openssl/bio.h>

pki_x509req::pki_x509req(const QString &name)
	: pki_x509super(name)
{
	request = X509_REQ_new();
	pki_openssl_error();
	pkiType = x509_req;
	resetX509count();
}

pki_x509req::pki_x509req(const pki_x509req *req)
	: pki_x509super(req)
{
	request = X509_REQ_dup(request);
	done = req->done;
	resetX509count();
	pki_openssl_error();
}

pki_x509req::~pki_x509req()
{
	if (request)
		X509_REQ_free(request);
}

QSqlError pki_x509req::insertSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_x509super::insertSqlData();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "INSERT INTO requests (item, hash, signed, request) "
		  "VALUES (?, ?, ?, ?)");
	q.bindValue(0, sqlItemId);
	q.bindValue(1, hash());
	q.bindValue(2, done ? 1 : 0);
	q.bindValue(3, i2d_b64());
	q.exec();
	return q.lastError();
}

void pki_x509req::markSigned(bool signe)
{
	XSqlQuery q;
	Transaction;
	TransThrow();

	SQL_PREPARE(q, "UPDATE requests SET signed=? WHERE item=?");
	q.bindValue(0, signe ? 1 : 0);
	q.bindValue(1, sqlItemId);
	q.exec();

	if (q.lastError().isValid())
		return;
	done = signe;
	AffectedItems(sqlItemId);
	TransCommit();
}

void pki_x509req::restoreSql(const QSqlRecord &rec)
{
	pki_x509super::restoreSql(rec);
	QByteArray ba = QByteArray::fromBase64(
				rec.value(VIEW_x509req_request).toByteArray());
	d2i(ba);
	done = rec.value(VIEW_x509req_signed).toBool();
}

QSqlError pki_x509req::deleteSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_x509super::deleteSqlData();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "DELETE FROM requests WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	return q.lastError();
}

void pki_x509req::createReq(pki_key *key, const x509name &dn,
				const digest &digest, extList el)
{
	QList<int> bad_nids; bad_nids << NID_authority_key_identifier <<
		NID_issuer_alt_name << NID_undef;

	EVP_PKEY *privkey = NULL;

	if (key->isPubKey()) {
		my_error(tr("Signing key not valid (public key)"));
		return;
	}

	X509_REQ_set_version(request, 0L);
	X509_REQ_set_pubkey(request, key->getPubKey());
	setSubject(dn);
	pki_openssl_error();

	foreach(int nid , bad_nids)
		el.delByNid(nid);

	el.delInvalid();

	if (el.count() > 0) {
		STACK_OF(X509_EXTENSION) *sk;
		sk = el.getStack();
		X509_REQ_add_extensions(request, sk);
		sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	}
	pki_openssl_error();

	privkey = key->decryptKey();
	X509_REQ_sign(request, privkey, digest.MD());
	pki_openssl_error();
	EVP_PKEY_free(privkey);
}

QString pki_x509req::getMsg(msg_type msg, int n) const
{
	/*
	 * We do not construct english sentences from fragments
	 * to allow proper translations.
	 * The drawback are all the slightly different duplicated messages
	 *
	 * %1 will be replaced by the internal name of the request
	 */

	switch (msg) {
	case msg_import: return tr("Successfully imported the PKCS#10 certificate request '%1'");
	case msg_delete: return tr("Delete the %n PKCS#10 certificate request(s): '%1'?", "", n);
	case msg_create: return tr("Successfully created the PKCS#10 certificate request '%1'");
	}
	return pki_base::getMsg(msg);
}

void pki_x509req::fromPEM_BIO(BIO *bio, const QString &name)
{
	X509_REQ *req;
	req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	openssl_error_msg(name);
	if (!req)
		throw errorEx();
	X509_REQ_free(request);
	request = req;
}

void pki_x509req::fload(const QString &fname)
{
	X509_REQ *_req;
	XFile file(fname);
	file.open_read();
	QByteArray ba(file.readAll());

	_req = PEM_read_bio_X509_REQ(BioByteArray(ba).ro(), NULL, NULL, NULL);
	if (!_req) {
		pki_ign_openssl_error();
		_req = d2i_X509_REQ_bio(BioByteArray(ba).ro(), NULL);
	}
	if (pki_ign_openssl_error() || !_req) {
		if (_req)
			X509_REQ_free(_req);
		throw errorEx(tr("Unable to load the certificate request in file %1. Tried PEM, DER and SPKAC format.").arg(fname));
	}

	X509_REQ_free(request);
	request = _req;
}

void pki_x509req::d2i(QByteArray &ba)
{
	X509_REQ *r= (X509_REQ*)d2i_bytearray(D2I_VOID(d2i_X509_REQ), ba);
	if (r) {
		X509_REQ_free(request);
		request = r;
	}
}

QByteArray pki_x509req::i2d() const
{
	return i2d_bytearray(I2D_VOID(i2d_X509_REQ), request);
}

void pki_x509req::addAttribute(int nid, QString content)
{
	if (content.isEmpty())
		return;

	ASN1_STRING *a = QStringToAsn1(content, nid);
	X509_REQ_add1_attr_by_NID(request, nid, a->type, a->data, a->length);
	ASN1_STRING_free(a);
	openssl_error_msg(QString("'%1' (%2)").arg(content).arg(OBJ_nid2ln(nid)));
}

x509name pki_x509req::getSubject() const
{
	x509name x(X509_REQ_get_subject_name(request));
	pki_openssl_error();
	return x;
}

int pki_x509req::sigAlg() const
{
	return X509_REQ_get_signature_nid(request);
}

void pki_x509req::setSubject(const x509name &n)
{
	X509_REQ_set_subject_name(request, n.get());
}

void pki_x509req::writeDefault(const QString &dirname) const
{
	XFile file(get_dump_filename(dirname, ".csr"));
	file.open_write();
	writeReq(file, true);
}

void pki_x509req::writeReq(XFile &file, bool pem) const
{
	BioByteArray b;
	if (!request)
		return;
	if (pem) {
		b += PEM_comment();
		PEM_write_bio_X509_REQ(b, request);
	} else {
		i2d_X509_REQ_bio(b, request);
	}
	pki_openssl_error();
	file.write(b);
}

bool pki_x509req::pem(BioByteArray &b)
{
	return PEM_write_bio_X509_REQ(b, request);
}

bool pki_x509req::verify() const
{
	EVP_PKEY *pkey = X509_REQ_get_pubkey(request);
	bool x = X509_REQ_verify(request,pkey) > 0;
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

extList pki_x509req::getV3ext() const
{
	extList el;
	STACK_OF(X509_EXTENSION) *sk;
	sk = X509_REQ_get_extensions(request);
	el.setStack(sk);
	sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	return el;
}

QString pki_x509req::getAttribute(int nid) const
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
	count = X509_ATTRIBUTE_count(att);
	for (int j = 0; j < count; j++)
		ret << asn1ToQString(X509_ATTRIBUTE_get0_type(att, j)->
		                    value.asn1_string);
	return ret.join(", ");
}

int pki_x509req::issuedCerts() const
{
	XSqlQuery q;
	int count = 0;

	if (x509count != -1)
		return x509count;

	pki_key *k = getPubKey();
	if (!k)
		return 0;
	QList<pki_x509 *> certs = Store.sqlSELECTpki<pki_x509>(
		"SELECT item FROM x509super LEFT JOIN items ON items.id = x509super.item "
		"WHERE key_hash=? AND items.type=?",
		QList<QVariant>() << QVariant(pubHash()) << QVariant(x509));

	foreach(pki_x509 *x, certs) {
		if (x->compareRefKey(k))
			count++;

		qDebug() << "Req:" << getIntName() << "Cert with hash"
			 << x->getIntName() << count;
	}
	delete k;
	x509count = count;
	return count;
}

void pki_x509req::collect_properties(QMap<QString, QString> &prp) const
{
	QString s = getAttribute(NID_pkcs9_unstructuredName);
	if (!s.isEmpty())
		prp["Unstructured Name"] = s;

	s = getAttribute(NID_pkcs9_challengePassword);
	if (!s.isEmpty())
		prp["Challenge Password"] = s;

	pki_x509super::collect_properties(prp);
	prp["Verify Ok"] = verify() ? "Yes" : "No";
}

void pki_x509req::print(BioByteArray &bba, enum print_opt opt) const
{
	pki_x509super::print(bba, opt);
	switch (opt) {
	case print_openssl_txt:
		X509_REQ_print(bba, request);
		break;
	case print_pem:
		PEM_write_bio_X509_REQ(bba, request);
		break;
	case print_coloured:
		break;
	}
}

QVariant pki_x509req::column_data(const dbheader *hd) const
{
	switch (hd->id) {
	case HD_req_signed:
		return QVariant(done ? tr("Signed") : tr("Unhandled"));
	case HD_req_unstr_name:
		return getAttribute(NID_pkcs9_unstructuredName);
	case HD_req_chall_pass:
		return getAttribute(NID_pkcs9_challengePassword);
	case HD_req_certs:
		return QVariant(issuedCerts());
	}
	return pki_x509super::column_data(hd);
}

QVariant pki_x509req::getIcon(const dbheader *hd) const
{
	switch (hd->id) {
	case HD_internal_name:
		return QVariant(QPixmap(hasPrivKey() ? ":reqkeyIco" : ":reqIco"));
	case HD_req_signed:
		if (done)
			return QVariant(QPixmap(":doneIco"));
		break;
	default:
		return pki_x509super::getIcon(hd);
	}
	return QVariant();
}

bool pki_x509req::visible() const
{
	if (pki_x509super::visible())
		return true;
	if (getAttribute(NID_pkcs9_unstructuredName).contains(limitPattern))
		return true;
	if (getAttribute(NID_pkcs9_challengePassword).contains(limitPattern))
		return true;
	return false;
}
