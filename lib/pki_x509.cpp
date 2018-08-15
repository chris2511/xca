/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_x509.h"
#include "pki_evp.h"
#include "pki_scard.h"
#include "db_base.h"
#include "func.h"
#include "base.h"
#include "exception.h"
#include "pass_info.h"
#include "widgets/MainWindow.h"
#include <QMessageBox>
#include <QDir>
#include <openssl/rand.h>

#include "openssl_compat.h"

QPixmap *pki_x509::icon[5];

pki_x509::pki_x509(X509 *c)
	:pki_x509super()
{
	init();
	cert = c;
	pki_openssl_error();
}

pki_x509::pki_x509(const pki_x509 *crt)
	:pki_x509super(crt->desc)
{
	init();
	cert = X509_dup(crt->cert);
	pki_openssl_error();
	psigner = crt->psigner;
	setRefKey(crt->getRefKey());
	caTemplateSqlId = crt->caTemplateSqlId;
	revocation = crt->revocation;
	crlDays = crt->crlDays;
	crlExpire = crt->crlExpire;
	pki_openssl_error();
}

pki_x509::pki_x509(const QString name)
	:pki_x509super(name)
{
	init();
	cert = X509_new();
	X509_set_version(cert, 2);
	pki_openssl_error();
}

QString pki_x509::getMsg(msg_type msg) const
{
	/*
	 * We do not construct english sentences from fragments
	 * to allow proper translations.
	 * The drawback are all the slightly different duplicated messages
	 *
	 * %1 will be replaced by the internal name of the certificate
	 */
	switch (msg) {
	case msg_import: return tr("Successfully imported the certificate '%1'");
	case msg_delete: return tr("Delete the certificate '%1'?");
	case msg_create: return tr("Successfully created the certificate '%1'");
	/* %1: Number of certs; %2: list of cert names */
	case msg_delete_multi: return tr("Delete the %1 certificates: %2?");
	}
	return pki_base::getMsg(msg);
}

QSqlError pki_x509::insertSqlData()
{
	XSqlQuery q;
	a1time now;
	pki_x509 *signer = findIssuer();
	QSqlError e = pki_x509super::insertSqlData();
	if (e.isValid())
		return e;

	SQL_PREPARE(q, "INSERT INTO certs (item, hash, iss_hash, serial, issuer, "
				"ca, cert) "
		  "VALUES (?, ?, ?, ?, ?, ?, ?)");
	q.bindValue(0, sqlItemId);
	q.bindValue(1, hash());
	q.bindValue(2, (uint)getIssuerName().hashNum());
	q.bindValue(3, getSerial().toHex());
	q.bindValue(4, signer ? signer->getSqlItemId() : QVariant());
	q.bindValue(5, (int)isCA());
	q.bindValue(6, i2d_b64());
	q.exec();
	MainWindow::reqs->resetX509count();
	if (!isCA())
		return q.lastError();

	SQL_PREPARE(q, "INSERT INTO authority (item, template, crlExpire, crlNo, crlDays) "
			"VALUES (?, ?, ?, 0, ?)");
	q.bindValue(0, sqlItemId);
	q.bindValue(1, caTemplateSqlId);
	q.bindValue(2, crlExpire.toPlain());
	q.bindValue(3, crlDays);
	q.exec();
	if (fromDataRevList.size() > 0)
		fromDataRevList.sqlUpdate(sqlItemId);
	return q.lastError();
}

void pki_x509::restoreSql(const QSqlRecord &rec)
{
	pki_x509super::restoreSql(rec);
	QByteArray ba = QByteArray::fromBase64(
				rec.value(VIEW_x509_cert).toByteArray());
	d2i(ba);
	signerSqlId = rec.value(VIEW_x509_issuer);
	crlNumber.set(rec.value(VIEW_x509_auth_crlNo).toUInt());
	crlExpire.fromPlain(rec.value(VIEW_x509_auth_crlExpire).toString());
	caTemplateSqlId = rec.value(VIEW_x509_auth_template);
	if (!rec.isNull(VIEW_x509_auth_crlDays))
		crlDays = rec.value(VIEW_x509_auth_crlDays).toInt();
	else
		crlDays = 30;
	if (!rec.isNull(VIEW_x509_revocation))
		revocation = x509rev(rec, VIEW_x509_revocation);
}

QSqlError pki_x509::deleteSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_x509super::deleteSqlData();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "DELETE FROM certs WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	e = q.lastError();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "DELETE FROM authority WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	e = q.lastError();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "UPDATE crls SET issuer=NULL WHERE issuer=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	e = q.lastError();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "UPDATE certs SET issuer=NULL WHERE issuer=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	e = q.lastError();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "DELETE FROM revocations WHERE caId=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	// Select affected items
	QList<pki_base*> list = db_base::sqlSELECTpki<pki_base>(
		"SELECT DISTINCT items.id FROM items, certs, crls "
		"WHERE (items.id = certs.item OR items.id = crls.item) "
		"AND crls.issuer = ? AND certs.issuer = ?",
		QList<QVariant>() << QVariant(sqlItemId)
				  << QVariant(sqlItemId));

	foreach(pki_base *pki, list)
		AffectedItems(pki->getSqlItemId());

	MainWindow::reqs->resetX509count();
	return q.lastError();
}

pki_x509 *pki_x509::findIssuer()
{
	XSqlQuery q;
	pki_x509 *issuer;
	unsigned hash;

	if ((issuer = getSigner()) != NULL)
		return issuer;
	// first check for self-signed
	if (verify(this))
		return this;

	hash = getIssuerName().hashNum();
	/* Select X509 CA certificates with subject-hash == hash */
	SQL_PREPARE(q, "SELECT x509super.item from x509super "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE certs.ca=1 AND x509super.subj_hash=?");
	q.bindValue(0, hash);
	q.exec();
	while (q.next()) {
		issuer = db_base::lookupPki<pki_x509>(q.value(0));
		if (!issuer) {
			qDebug("Certificate with id %d not found",
                                q.value(0).toInt());
		}
		if (verify(issuer)) {
			return issuer;
		}
	}
	return NULL;
}

void pki_x509::fromPEM_BIO(BIO *bio, QString)
{
	X509 *_cert;
	_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	pki_openssl_error();
	X509_free(cert);
	cert = _cert;
}

void pki_x509::fload(const QString fname)
{
	FILE *fp = fopen_read(fname);
	X509 *_cert;
	if (!fp) {
		fopen_error(fname);
		return;
	}
	_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	if (!_cert) {
		pki_ign_openssl_error();
		rewind(fp);
		_cert = d2i_X509_fp(fp, NULL);
	}
	fclose(fp);
	if (pki_ign_openssl_error() ) {
		if (_cert)
			X509_free(_cert);
		throw errorEx(tr("Unable to load the certificate in file %1. Tried PEM and DER certificate.").arg(fname));
	}
	X509_free(cert);
	cert = _cert;
	autoIntName();
	if (getIntName().isEmpty())
		setIntName(rmslashdot(fname));
}

pki_x509::~pki_x509()
{
	if (cert) {
		X509_free(cert);
	}
	pki_openssl_error();
}

void pki_x509::init()
{
	psigner = NULL;
	caTemplateSqlId = QVariant();
	crlDays = 30;
	crlExpire.setUndefined();
	cert = NULL;
	pkiType = x509;
}

void pki_x509::setSerial(const a1int &serial)
{
	X509_set_serialNumber(cert, serial.get());
	pki_openssl_error();
}

a1int pki_x509::getSerial() const
{
	a1int a(X509_get_serialNumber(cert));
	pki_openssl_error();
	return a;
}

pki_x509 *pki_x509::getBySerial(const a1int &a) const
{
	foreach(pki_base *p, childItems) {
		pki_x509 *pki = static_cast<pki_x509 *>(p);
		if (a == pki->getSerial())
			return pki;
	}
	return NULL;
}

a1int pki_x509::hashInfo(const EVP_MD *md) const
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned len = 0;

	if (!X509_digest(cert, md, digest, &len))
		pki_openssl_error();
	a1int a;
	a.setRaw(digest,len);
	return a;
}

void pki_x509::load_token(pkcs11 &p11, CK_OBJECT_HANDLE object)
{
	QString desc;

	pk11_attr_ulong type(CKA_CERTIFICATE_TYPE);
	p11.loadAttribute(type, object);
	if (type.getValue() != CKC_X_509)
		throw errorEx(QString("Unsupported Certificate type %1"
			).arg(type.getValue()));

	try {
		pk11_attr_data label(CKA_LABEL);
		p11.loadAttribute(label, object);
		desc = label.getText();
	} catch(errorEx &err) {
		qDebug("No Cert Label: %s", err.getCString());
		// IGNORE
	}
	pk11_attr_data x509(CKA_VALUE);
	p11.loadAttribute(x509, object);
	QByteArray der = x509.getData();
	d2i(der);

	if (desc.isEmpty()) {
		try {
			x509name xn;

			pk11_attr_data subj(CKA_SUBJECT);
			p11.loadAttribute(subj, object);
			QByteArray der = subj.getData();
			xn.d2i(der);
			desc = xn.getMostPopular();
			pki_openssl_error();
		} catch(errorEx &err) {
			qDebug("No Cert Subject: %s", err.getCString());
			// IGNORE
		}
	}
	setIntName(desc);
	pkiSource = token;
	pki_openssl_error();
}

void pki_x509::d2i(QByteArray &ba)
{
        X509 *c = (X509*)d2i_bytearray(D2I_VOID(d2i_X509), ba);
	if (c) {
		X509_free(cert);
		cert = c;
	}
	pki_openssl_error();
}

QByteArray pki_x509::i2d() const
{
	return i2d_bytearray(I2D_VOID(i2d_X509), cert);
}

void pki_x509::store_token(bool alwaysSelect)
{
	pki_scard *card = NULL;
	slotid slot;
	x509name xname;
	QList<CK_OBJECT_HANDLE> objects;

	pkcs11 p11;

	if (!privkey || !privkey->isToken() || alwaysSelect) {
		if (!p11.selectToken(&slot, NULL))
			return;
	} else {
		card = dynamic_cast<pki_scard *>(privkey);
		if (!card || !card->prepare_card(&slot))
			return;
	}

	pk11_attlist p11_atts;
	p11_atts <<
		pk11_attr_ulong(CKA_CLASS, CKO_CERTIFICATE) <<
		pk11_attr_ulong(CKA_CERTIFICATE_TYPE, CKC_X_509) <<
		pk11_attr_data(CKA_VALUE, i2d());

	p11.startSession(slot, true);

	QList<CK_OBJECT_HANDLE> objs = p11.objectList(p11_atts);
	if (objs.count() != 0) {
		XCA_WARN(tr("This certificate is already on the security token"));
		return;
	}

	p11_atts <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_bool(CKA_PRIVATE, false) <<
		pk11_attr_data(CKA_SUBJECT, getSubject().i2d()) <<
		pk11_attr_data(CKA_ISSUER, getIssuerName().i2d()) <<
		pk11_attr_data(CKA_SERIAL_NUMBER, getSerial().i2d()) <<
		pk11_attr_data(CKA_LABEL, desc.toUtf8()) <<
		(card ? card->getIdAttr() : p11.findUniqueID(CKO_CERTIFICATE));

	if (p11.tokenLogin(p11.tokenInfo().label(), false).isNull())
		return;

	p11.createObject(p11_atts);
}

void pki_x509::deleteFromToken()
{
	pki_scard *card = dynamic_cast<pki_scard *>(privkey);
	slotidList p11_slots;

	if (!card || !pkcs11::loaded())
		return;

	if (privkey && privkey->isToken()) {
		slotid slot;
		if (!card->prepare_card(&slot))
			return;
		p11_slots << slot;
	} else {
		pkcs11 p11;
		p11_slots = p11.getSlotList();
	}
	for (int i=0; i<p11_slots.count(); i++) {
		deleteFromToken(p11_slots[i]);
	}
}

pk11_attlist pki_x509::objectAttributes()
{
	pk11_attlist attrs;
        attrs <<
                pk11_attr_ulong(CKA_CLASS, CKO_CERTIFICATE) <<
                pk11_attr_ulong(CKA_CERTIFICATE_TYPE, CKC_X_509) <<
                pk11_attr_data(CKA_VALUE, i2d());
	return attrs;
}

void pki_x509::deleteFromToken(slotid slot)
{
	pkcs11 p11;
	p11.startSession(slot, true);

	pk11_attlist atts = objectAttributes();
	QList<CK_OBJECT_HANDLE> objs = p11.objectList(atts);
	if (!objs.count())
		return;

	tkInfo ti = p11.tokenInfo();
	if (!XCA_YESNO(tr("Delete the certificate '%1' from the token '%2 (#%3)'?").
		arg(getIntName()).arg(ti.label()).arg(ti.serial())))
	{
		return;
	}
	if (p11.tokenLogin(ti.label(), false).isNull())
		return;

	p11.deleteObjects(objs);
}

int pki_x509::renameOnToken(slotid slot, QString name)
{

	pkcs11 p11;
	p11.startSession(slot, true);
	pk11_attlist attrs = objectAttributes();

	QList<CK_OBJECT_HANDLE> objs = p11.objectList(attrs);
	if (!objs.count())
		return 0;

	pk11_attr_data label(CKA_LABEL, name.toUtf8());
	tkInfo ti = p11.tokenInfo();
	if (p11.tokenLogin(ti.label(), false).isNull())
                return 0;
	p11.storeAttribute(label, objs[0]);
	return 1;
}

void pki_x509::setNotBefore(const a1time &a)
{
	a1time t(a);
	X509_set_notBefore(cert, t.get_utc());
	pki_openssl_error();
}

void pki_x509::setNotAfter(const a1time &a)
{
	a1time t(a);
	X509_set_notAfter(cert, t.get_utc());
	pki_openssl_error();
}

a1time pki_x509::getNotBefore() const
{
	a1time a(X509_get_notBefore(cert));
	return a;
}

a1time pki_x509::getNotAfter() const
{
	a1time a(X509_get_notAfter(cert));
	return a;
}

x509name pki_x509::getSubject() const
{
	x509name x(X509_get_subject_name(cert));
	pki_openssl_error();
	return x;
}

x509name pki_x509::getIssuerName() const
{
	x509name x(X509_get_issuer_name(cert));
	pki_openssl_error();
	return x;
}

void pki_x509::setSubject(const x509name &n)
{
	X509_set_subject_name(cert, n.get());
	pki_openssl_error();
}

void pki_x509::setIssuer(const x509name &n)
{
	X509_set_issuer_name(cert, n.get());
	pki_openssl_error();
}

bool pki_x509::addV3ext(const x509v3ext &e, bool skip_existing)
{
	if (!e.isValid())
		return false;
	if (skip_existing && X509_get_ext_by_NID(cert, e.nid(), -1) != -1)
		return false;
	X509_EXTENSION *ext = e.get();
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	pki_openssl_error();
	return true;
}

void pki_x509::delSigner(pki_base *s)
{
	if (s == psigner)
		psigner = NULL;
}

bool pki_x509::isCA() const
{
	bool ca;
	int crit;
	BASIC_CONSTRAINTS *bc = (BASIC_CONSTRAINTS *)
		X509_get_ext_d2i(cert, NID_basic_constraints, &crit, NULL);
	pki_openssl_error();
	ca = bc && bc->ca;
	if (bc)
		BASIC_CONSTRAINTS_free(bc);
	return ca;
}

bool pki_x509::canSign() const
{
	if (!privkey || privkey->isPubKey())
		return false;
	if (privkey->isToken() && !pkcs11::loaded())
		return false;
	return isCA();
}

bool pki_x509::hasExtension(int nid) const
{
	return getV3ext().idxByNid(nid) != -1;
}

void pki_x509::sign(pki_key *signkey, const EVP_MD *digest)
{
	EVP_PKEY *tkey;
	if (!signkey) {
		my_error(tr("There is no key for signing !"));
	}
	tkey = signkey->decryptKey();
	pki_openssl_error();
	X509_sign(cert, tkey, digest);
	pki_openssl_error();
	EVP_PKEY_free(tkey);
	pki_openssl_error();
}

void pki_x509::fromData(const unsigned char *p, db_header_t *head)
{
	int version, size;
	bool isRevoked = false;

	version = head->version;
	size = head->len - sizeof(db_header_t);

	QByteArray ba((const char*)p, size);

	d2i(ba);
	pki_openssl_error();
	/* trust = */ db::intFromData(ba);
	if (version < 4) {
		a1time revoked;
		isRevoked = db::boolFromData(ba);
		revoked.d2i(ba);
		pki_openssl_error();
		if (isRevoked) {
			revocation.setDate(revoked);
			revocation.setSerial(getSerial());
		}
	}
	pki_openssl_error();
	/* Superflous CaSerial = */db::stringFromData(ba);
	QString caTemplate = db::stringFromData(ba);
	crlDays = db::intFromData(ba);
	crlExpire.d2i(ba);
	pki_openssl_error();
	if (version > 1)
		/* randomSerial = */ db::boolFromData(ba);
	if (version > 2)
		crlNumber.setHex(db::stringFromData(ba));
	pki_openssl_error();
	if (version > 2 && version < 4) {
		// load own revocation info, to tell daddy about it
		a1time invalDate;
		QString revoke_reason = db::stringFromData(ba);
		invalDate.d2i(ba);
		pki_openssl_error();
		if (isRevoked) {
			revocation.setReason(revoke_reason);
			revocation.setInvalDate(invalDate);
		}
	}
	pki_openssl_error();
	if (version > 3) {
		fromDataRevList.fromBA(ba);
		pki_openssl_error();
	}
	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
	pki_openssl_error();

	XSqlQuery q;
	SQL_PREPARE(q, "SELECT id FROM items WHERE name=? AND type=?");
	q.bindValue(0, caTemplate);
	q.bindValue(1, tmpl);
	q.exec();
	if (q.next())
		caTemplateSqlId = q.value(0);
}


void pki_x509::writeDefault(const QString fname)
{
	writeCert(get_dump_filename(fname, ".crt"), true, false);
}

void pki_x509::writeCert(const QString fname, bool PEM, bool append)
{
	FILE *fp;
	const char *p = "wb";
	if (append)
		p = "ab";
	fp = fopen(QString2filename(fname), p);
	if (fp != NULL) {
		if (cert){
			if (PEM)
				PEM_write_X509(fp, cert);
			else
				i2d_X509_fp(fp, cert);
		}
		fclose(fp);
		pki_openssl_error();
	} else
		fopen_error(fname);
}

QString pki_x509::getIndexEntry()
{
	QString flag = NULL;
	bool revoked = isRevoked();

	if (revoked)
		flag = "R";
	else if (checkDate())
		flag = "V";
	else
		flag = "E";

	return QString("%1\t%2\t%3\t%4\tunknown\t%5\n").arg(
		flag, getNotAfter().toPlainUTC(),
		revoked ? revocation.getDate().toPlainUTC() : "",
		getSerial(),
		QString(X509_NAME_oneline(getSubject().get(), NULL, 0)));
}

BIO *pki_x509::pem(BIO *b, int format)
{
	(void)format;
	if (!b)
		b = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(b, cert);
	return b;
}

bool pki_x509::cmpIssuerAndSerial(pki_x509 *refcert)
{
	bool ret =  X509_issuer_and_serial_cmp(cert, refcert->cert);
	pki_openssl_error();
	return ret;

}

bool pki_x509::verify_only(pki_x509 *signer)
{
	X509_NAME *subject = X509_get_subject_name(signer->cert);
	X509_NAME *issuer = X509_get_issuer_name(cert);
	pki_openssl_error();
	if (X509_NAME_cmp(subject, issuer)) {
		return false;
	}
	EVP_PKEY *pub = X509_get_pubkey(signer->cert);
	if (!pub) {
		pki_ign_openssl_error();
		return false;
	}
	int i = X509_verify(cert, pub);
	pki_ign_openssl_error();
	return i>0;
}

bool pki_x509::verify(pki_x509 *signer)
{
	if (psigner == signer)
		return true;
	if ((psigner != NULL) || (signer == NULL))
		return false;
	if (signer == this &&
	    signerSqlId == sqlItemId &&
	    signerSqlId != QVariant())
		return true;

	if (verify_only(signer)) {
		int idx;
		x509rev r;
		x509revList rl(revocation);
		r.setSerial(getSerial());
		psigner = signer;
		signerSqlId = psigner->sqlItemId;
		psigner->mergeRevList(rl);
		rl = psigner->getRevList();
		idx = rl.indexOf(r);
		if (idx != -1)
			revocation = rl[idx];
		return true;
	}
	return false;
}

x509revList pki_x509::getRevList() const
{
	return isCA() ? x509revList::fromSql(sqlItemId) : x509revList();
}

void pki_x509::mergeRevList(x509revList &l)
{
	x509revList revList = getRevList();
	revList.merge(l);

	if (revList.merged)
		revList.sqlUpdate(sqlItemId);
}

void pki_x509::setRevocations(const x509revList &rl)
{
	x509rev rev;
	x509revList revList = rl;

	foreach(pki_base *p, childItems) {
		pki_x509 *pki = static_cast<pki_x509 *>(p);
		rev.setSerial(pki->getSerial());
		int idx = revList.indexOf(rev);
		if (idx != -1)
			pki->revocation = revList[idx];
		else
			pki->revocation = x509rev();
	}
	revList.sqlUpdate(sqlItemId);
}

pki_key *pki_x509::getPubKey() const
{
	EVP_PKEY *pkey = X509_get_pubkey(cert);
	pki_ign_openssl_error();
	if (pkey == NULL)
		return NULL;
	pki_evp *key = new pki_evp(pkey);
	pki_openssl_error();
	return key;
}

bool pki_x509::compareNameAndKey(pki_x509 *other)
{
	int r;
	X509_NAME *s1, *s2;
	EVP_PKEY *pub1, *pub2;

	if (!cert || !other->cert)
		return false;
	s1 = X509_get_subject_name(cert);
	s2 = X509_get_subject_name(other->cert);
	pki_openssl_error();
	if (!s1 || !s2)
		return false;
	/* X509_NAME_cmp returns 0 if they match */
	r = X509_NAME_cmp(s1, s2);
	pki_openssl_error();
	if (r)
		return false;
	pub1 = X509_get_pubkey(cert);
	pub2 = X509_get_pubkey(other->cert);
	pki_ign_openssl_error();
	if (!pub1 || !pub2)
		return false;
	/* EVP_PKEY_cmp() return 1 if the keys match */
	r = EVP_PKEY_cmp(pub1, pub2);
	pki_openssl_error();
	return r == 1;
}

void pki_x509::setPubKey(pki_key *key)
{
	X509_set_pubkey(cert, key->getPubKey());
	pki_openssl_error();
}

QString pki_x509::fingerprint(const EVP_MD *digest) const
{
	unsigned int n;
	unsigned char md[EVP_MAX_MD_SIZE];

	pki_openssl_error();
	X509_digest(cert, digest, md, &n);
	pki_openssl_error();
	return formatHash(md, n);
}

bool pki_x509::checkDate()
{
	a1time n, b, a;

	n = a1time::now(),
	b = getNotBefore();
	a = getNotAfter();
	pki_openssl_error();

	if (!a.isValid() || !b.isValid())
		return false;
	if (!a.isUndefined() && (a < n))
		return false;
	if (b > n)
		return false;
	pki_openssl_error();
	return true;
}

extList pki_x509::getV3ext() const
{
	extList el;
	el.setStack(X509_get0_extensions(cert));
	return el;
}

x509v3ext pki_x509::getExtByNid(int nid) const
{
	extList el = getV3ext();
	int i = el.idxByNid(nid);

	try {
		pki_openssl_error();
	} catch(errorEx &err) {
		XCA_WARN(err.getString());
	}
	if (i == -1)
		return x509v3ext();
	return el[i];
}

int pki_x509::sigAlg() const
{
	return X509_get_signature_nid(cert);
}

pki_x509 *pki_x509::getSigner()
{
	return psigner;
}

bool pki_x509::isRevoked() const
{
	return revocation.isValid();
}

void pki_x509::setRevoked(const x509rev &revok)
{
	revocation = revok;
}

bool pki_x509::caAndPathLen(bool *ca, a1int *pathlen, bool *hasLen) const
{
	x509v3ext e = getExtByNid(NID_basic_constraints);
	if (e.nid() != NID_basic_constraints)
		return false;
	BASIC_CONSTRAINTS *bc = (BASIC_CONSTRAINTS *)e.d2i();
	if (hasLen)
		*hasLen = bc->pathlen ? true : false;
	if (pathlen && bc->pathlen)
		pathlen->set(bc->pathlen);
	if (ca)
		*ca = bc->ca;
	BASIC_CONSTRAINTS_free(bc);
	pki_openssl_error();
	return true;
}

QVariant pki_x509::column_data(const dbheader *hd) const
{
	switch (hd->id) {
		case HD_cert_serial:
			return QVariant(getSerial().toHex());
		case HD_cert_md5fp:
			return QVariant(fingerprint(EVP_md5()));
		case HD_cert_sha1fp:
			return QVariant(fingerprint(EVP_sha1()));
		case HD_cert_sha256fp:
			return QVariant(fingerprint(EVP_sha256()));
		case HD_cert_ca: {
			a1int len;
			bool ca, haslen;
			if (caAndPathLen(&ca, &len, &haslen)) {
				if (ca && haslen)
					return QVariant(len.toDec());
				if (!ca)
					return QVariant(tr("No"));
				else
					return QVariant(tr("Yes"));
			}
			break;
		}
	}
	return pki_x509super::column_data(hd);
}

a1time pki_x509::column_a1time(const dbheader *hd) const
{
	switch (hd->id) {
		case HD_cert_notBefore:
			return getNotBefore();
		case HD_cert_notAfter:
			return getNotAfter();
		case HD_cert_revocation:
			if (isRevoked())
				return revocation.getDate();
			break;
		case HD_cert_crl_expire:
			if (canSign())
				return crlExpire;
			break;
	}
	return pki_base::column_a1time(hd);
}

QStringList pki_x509::icsVEVENT() const
{
	return pki_base::icsVEVENT(getNotAfter(),
		tr("Renew certificate: %1").arg(getIntName()),
		tr("The XCA certificate '%1', issued on %2 "
		   "will expire on %3.\n"
		   "It is stored in the XCA database '%4'")
			.arg(getIntName())
			.arg(getNotBefore().toPretty())
			.arg(getNotAfter().toPretty())
			.arg(currentDB)
	);
}

QStringList pki_x509::icsVEVENT_ca() const
{
	QStringList ics;
	ics << icsVEVENT();
	foreach(pki_base *p, childItems) {
		pki_x509 *pki = static_cast<pki_x509 *>(p);
		if (pki->getNotAfter() > a1time() && !isRevoked())
			ics << pki->icsVEVENT();
	}

	ics << pki_base::icsVEVENT(crlExpire,
		tr("CRL Renewal of CA '%1' due").arg(getIntName()),
		tr("The latest CRL issued by the CA '%1' will expire on %2.\n"
		  "It is stored in the XCA database '%3'")
			.arg(getIntName())
			.arg(crlExpire.toPretty())
			.arg(currentDB)
	);
	return ics;
}

QVariant pki_x509::getIcon(const dbheader *hd) const
{
	int pixnum = 0;
	bool ca;

	switch (hd->id) {
	case HD_cert_ca:
		if (!caAndPathLen(&ca, NULL, NULL))
			return QVariant();
		if (!ca)
			return QVariant();
		pixnum = 4;
		break;
	case HD_internal_name:
		if (hasPrivKey())
			pixnum += 1;
		if (isRevoked())
			pixnum += 2;
		break;
	default:
		return pki_x509super::getIcon(hd);
	}
	return QVariant(*icon[pixnum]);
}

bool pki_x509::visible() const
{
	if (pki_x509super::visible())
		return true;
	if (getIssuerName().search(limitPattern))
		return true;
	if (fingerprint(EVP_md5()).contains(limitPattern))
		return true;
	if (fingerprint(EVP_sha1()).contains(limitPattern))
		return true;
	if (fingerprint(EVP_sha256()).contains(limitPattern))
		return true;
	if (getSerial().toHex().contains(limitPattern))
		return true;
	return false;
}

QVariant pki_x509::bg_color(const dbheader *hd) const
{
#define BG_RED     QBrush(QColor(255,  0,  0))
#define BG_YELLOW  QBrush(QColor(255,255,  0))
#define BG_CYAN    QBrush(QColor(127,255,212))

	if (Settings["no_expire_colors"])
		return QVariant();

	QString unit, cert_expiry_num = Settings["cert_expiry"];
	unit = cert_expiry_num.right(1);
	cert_expiry_num.chop(1);
	int n = cert_expiry_num.toInt();

	a1time nb, na, now, certwarn;

	nb = getNotBefore();
	na = getNotAfter();
	now = a1time::now();

	if (unit == "%") {
		quint64 lifetime = nb.secsTo(na);
		certwarn = nb.addSecs(lifetime *n /100);
	} else if (unit == "D") {
		certwarn = na.addDays(-n);
	} else if (unit == "W") {
		certwarn = na.addDays(-n*7);
	}
	switch (hd->id) {
		case HD_cert_notBefore:
			if (nb > now || !nb.isValid() || nb.isUndefined())
				return QVariant(BG_RED);
			break;
		case HD_cert_notAfter: {
			if (na.isUndefined())
				return QVariant(BG_CYAN);
			if (na < now)
				return QVariant(BG_RED);
			if (certwarn < now)
				return QVariant(BG_YELLOW);
			break;
		}
		case HD_cert_crl_expire:
			if (canSign()) {
				QDateTime crlwarn, crlex;
				crlex = crlExpire;
				if (!crlExpire.isUndefined()) {
					crlwarn = crlex.addSecs(-2 *60*60*24);
					if (crlex < now)
						return QVariant(BG_RED);
					if (crlwarn < now || !crlex.isValid())
						return QVariant(BG_YELLOW);
				}
			}
	}
	return QVariant();
}
