/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_x509.h"
#include "pki_x509req.h"
#include "pki_evp.h"
#include "pki_scard.h"
#include "pki_crl.h"
#include "db_base.h"
#include "func.h"
#include "base.h"
#include "exception.h"
#include "pass_info.h"

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

pki_x509::pki_x509(X509 *c)
	:pki_x509super(), cert(c)
{
	init();
}

pki_x509::pki_x509(const pki_x509 *crt)
	:pki_x509super(crt)
{
	init();
	cert = X509_dup(crt->cert);
	pki_openssl_error();
	issuerSqlId = crt->issuerSqlId;
	setRefKey(crt->getRefKey());
	caTemplateSqlId = crt->caTemplateSqlId;
	revocation = crt->revocation;
	crlDays = crt->crlDays;
	crlExpire = crt->crlExpire;
	pki_openssl_error();
}

pki_x509::pki_x509(const QString &name)
	:pki_x509super(name)
{
	init();
	cert = X509_new();
	X509_set_version(cert, 2);
	pki_openssl_error();
}

QString pki_x509::getMsg(msg_type msg, int n) const
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
	case msg_delete: return tr("Delete the %n certificate(s): '%1'?", "", n);
	case msg_create: return tr("Successfully created the certificate '%1'");
	}
	return pki_base::getMsg(msg);
}

void pki_x509::resetX509ReqCount() const
{
	QList<pki_x509req *> reqs = Store.sqlSELECTpki<pki_x509req>(
		"SELECT item FROM x509super LEFT JOIN items ON items.id = x509super.item "
		"WHERE key_hash=? AND items.type=?",
		QList<QVariant>() << QVariant(pubHash()) << QVariant(x509_req));

	foreach(pki_x509req *req, reqs)
		req->resetX509count();
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
	q.bindValue(2, getIssuerName().hashNum());
	q.bindValue(3, getSerial().toHex());
	q.bindValue(4, signer ? signer->getSqlItemId() : QVariant());
	q.bindValue(5, (int)isCA());
	q.bindValue(6, i2d_b64());
	q.exec();

	resetX509ReqCount();

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
	issuerSqlId = rec.value(VIEW_x509_issuer);
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
	QStringList tasks; tasks
		<< "DELETE FROM certs WHERE item=?"
		<< "DELETE FROM authority WHERE item=?"
		<< "UPDATE crls SET issuer=NULL WHERE issuer=?"
		<< "UPDATE certs SET issuer=NULL WHERE issuer=?"
		<< "DELETE FROM revocations WHERE caId=?"
		<< "DELETE FROM takeys WHERE item=?"
		;
	foreach(QString task, tasks) {
		SQL_PREPARE(q, task);
		q.bindValue(0, sqlItemId);
		q.exec();
		e = q.lastError();
		if (e.isValid())
			return e;
	}
	// Select affected items
	q = Store.sqlSELECTpki(
		"SELECT DISTINCT items.id FROM items, certs, crls "
		"WHERE (items.id = certs.item OR items.id = crls.item) "
		"AND crls.issuer = ? AND certs.issuer = ?",
		QList<QVariant>() << QVariant(sqlItemId)
				  << QVariant(sqlItemId));

	while (q.next())
		AffectedItems(q.value(0));

	resetX509ReqCount();
	return q.lastError();
}

pki_x509 *pki_x509::findIssuer()
{
	XSqlQuery q;
	pki_x509 *issuer = NULL;
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
		pki_x509 *an_issuer = Store.lookupPki<pki_x509>(q.value(0));
		qDebug() << "Possible Issuer of" << *this << *an_issuer << an_issuer->getNotAfter();
		if (!an_issuer) {
			qDebug("Certificate with id %d not found", q.value(0).toInt());
			continue;
		}
		if (verify_only(an_issuer)) {
			if (!issuer || (issuer->getNotAfter() < an_issuer->getNotAfter())) {
				qDebug() << "New issuer of" << *this << *an_issuer << an_issuer->getNotAfter();
				issuer = an_issuer;
			}
		}
	}
	verify(issuer);
	return issuer;
}

void pki_x509::fromPEM_BIO(BIO *bio, const QString &fname)
{
	X509 *_cert;
	_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	openssl_error_msg(fname);
	if (!_cert)
		throw errorEx();
	X509_free(cert);
	cert = _cert;
}

void pki_x509::fload(const QString &fname)
{
	X509 *_cert;
	XFile file(fname);
	file.open_read();
	QByteArray ba(file.readAll());

	_cert = PEM_read_bio_X509(BioByteArray(ba).ro(), NULL, NULL, NULL);
	if (!_cert) {
		pki_ign_openssl_error();
		_cert = d2i_X509_bio(BioByteArray(ba).ro(), NULL);
	}
	if (pki_ign_openssl_error() || !_cert) {
		if (_cert)
			X509_free(_cert);
		throw errorEx(tr("Unable to load the certificate in file %1. Tried PEM and DER certificate.").arg(fname));
	}
	X509_free(cert);
	cert = _cert;
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
	crlExpire.setUndefined();
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

#define D5 "-----"
#define OVPN_TA_KEY "OpenVPN Static key V1"

QString pki_x509::getTaKey()
{
	XSqlQuery q;
	QByteArray b;
	pki_x509 *issuer = getSigner();
	if (!isCA() && issuer && issuer != this)
		return issuer->getTaKey();

	Transaction;
	if (!TransBegin())
		return QString();

	SQL_PREPARE(q, "SELECT value FROM takeys WHERE item = ?");
	q.bindValue(0, sqlItemId);
	q.exec();
	if (q.next()) {
		b = QByteArray::fromBase64(q.value(0).toByteArray());
		qDebug() << "Loaded TA key" << this << b.size() << QString::fromLatin1(b.toHex()).left(6);
	} else {
		b.resize(2048/8);
		RAND_bytes((unsigned char*)b.data(), 2048/8);
		SQL_PREPARE(q, "INSERT INTO takeys (item, value) VALUES ( ?, ? )");
		q.bindValue(0, sqlItemId);
		q.bindValue(1, b.toBase64());
		q.exec();
		qDebug() << "Generated TA key" << this << b.size() << QString::fromLatin1(b.toHex()).left(6);
	}
	TransCommit();
	QString takey(D5 "BEGIN " OVPN_TA_KEY D5 "\n");
	QString hex(QString::fromLatin1(b.toHex()));
	for (int i=0; i<16; i++)
		takey += hex.mid(32*i, 32) + "\n";
	takey += D5 "END " OVPN_TA_KEY D5 "\n";
	return takey;
}

bool pki_x509::importTaKey(const QByteArray &takey)
{
	int start = takey.indexOf(D5 "BEGIN " OVPN_TA_KEY D5);
	int end = takey.indexOf(D5 "END " OVPN_TA_KEY D5);
	QByteArray data, existing_takey;
	bool existed= false;

	if (start >= 0 && end > 0 && start < end) {
		start += sizeof D5 "BEGIN " OVPN_TA_KEY D5;
		data = QByteArray::fromHex(takey.mid(start, end-start));
		qDebug() << "TAKEY content" << start << end << data.size();
	}
	if (data.size() != 2048/8) {
		XCA_ERROR(tr("Invalid OpenVPN tls-auth key"));
		return false;
	}

	XSqlQuery q;
	Transaction;
	if (!TransBegin())
		return false;

	SQL_PREPARE(q, "SELECT value FROM takeys WHERE item = ?");
	q.bindValue(0, sqlItemId);
	q.exec();
	if (q.next()) {
		existed = true;
		existing_takey = QByteArray::fromBase64(q.value(0).toByteArray());
		qDebug() << "Existing TA key" << this << existing_takey.size()
				<< QString::fromLatin1(existing_takey.toHex()).left(6);
	}
	if (existing_takey != data) {
		if (existed)
			SQL_PREPARE(q, "UPDATE takeys SET value = ? WHERE item = ?");
		else
			SQL_PREPARE(q, "INSERT INTO takeys (item, value) VALUES ( ?, ? )");
		q.bindValue(0, sqlItemId);
		q.bindValue(1, data.toBase64());
		q.exec();
	}
	TransCommit();
	QSqlError e = q.lastError();
	if (e.isValid()) {
		XCA_ERROR(tr("Failed to import tls-auth key"));
		return false;
	} else if (existing_takey == data) {
		XCA_INFO(tr("Same tls-auth key already stored for this CA"));
	} else if (existing_takey.isEmpty()) {
		XCA_INFO(tr("New tls-auth key successfully imported"));
	} else {
		XCA_INFO(tr("Existing tls-auth key successfully replaced"));
	}
	return true;
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

	pki_key *privkey = getRefKey();
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

	if (!p11.tokenLoginForModification())
		return;

	p11.createObject(p11_atts);
}

void pki_x509::deleteFromToken()
{
	pki_key *privkey = getRefKey();
	pki_scard *card = dynamic_cast<pki_scard *>(privkey);
	slotidList p11_slots;

	if (!card || !pkcs11::libraries.loaded())
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

void pki_x509::deleteFromToken(const slotid &slot)
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
	if (!p11.tokenLoginForModification())
		return;

	p11.deleteObjects(objs);
}

int pki_x509::renameOnToken(const slotid &slot, const QString &name)
{

	pkcs11 p11;
	p11.startSession(slot, true);
	pk11_attlist attrs = objectAttributes();

	QList<CK_OBJECT_HANDLE> objs = p11.objectList(attrs);
	if (!objs.count())
		return 0;

	pk11_attr_data label(CKA_LABEL, name.toUtf8());
	if (!p11.tokenLoginForModification())
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
	if (s && (s->getSqlItemId() == issuerSqlId))
		issuerSqlId = QVariant();
}

bool pki_x509::isCA() const
{
	return X509_check_ca(cert) == 1;
}

bool pki_x509::canSign() const
{
	pki_key *privkey = getRefKey();
	if (!privkey || privkey->isPubKey())
		return false;
	if (privkey->isToken() && !pkcs11::libraries.loaded())
		return false;
	return isCA();
}

bool pki_x509::hasExtension(int nid) const
{
	return getV3ext().idxByNid(nid) != -1;
}

void pki_x509::sign(pki_key *signkey, const digest &digest)
{
	EVP_PKEY *tkey;
	if (!signkey) {
		my_error(tr("There is no key for signing !"));
	}
	tkey = signkey->decryptKey();
	pki_openssl_error();
	X509_sign(cert, tkey, digest.MD());
	pki_openssl_error();
	EVP_PKEY_free(tkey);
	pki_openssl_error();
}

void pki_x509::writeDefault(const QString &dirname) const
{
	XFile file(get_dump_filename(dirname, ".crt"));
	file.open_write();
	writeCert(file, true);
}

void pki_x509::writeCert(XFile &file, bool PEM) const
{
	if (!cert)
		return;
	BioByteArray b;
	if (PEM) {
		b += PEM_comment();
		PEM_write_bio_X509(b, cert);
	} else {
		i2d_X509_bio(b, cert);
	}
	pki_openssl_error();
	file.write(b);
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

bool pki_x509::pem(BioByteArray &b)
{
	const pki_export *xport = pki_export::by_id(Settings["CertFormat"]);

	if (xport->match_all(F_PEM | F_CHAIN)) {
		pki_x509 *iss, *prev;
		for (iss = this, prev = nullptr; iss && iss != prev;
			prev = iss, iss = iss->getSigner())
		{
			qDebug() << "Exporting to ClipBoard" << iss->getIntName();
			if (!PEM_write_bio_X509(b, iss->cert))
				return false;
		}
	} else if (xport->match_all(F_PEM | F_PRIVATE)) {
		pki_key *key = getRefKey();
		if (!key || !PEM_write_bio_X509(b, cert))
			return false;
		return key->pem(b, xport);
	} else {
		return PEM_write_bio_X509(b, cert);
	}
	return true;
}

void pki_x509::fillJWK(QJsonObject &json, const pki_export *xport) const
{
	QByteArray der = i2d();
	pki_key *key = getPubKey();

	key->fillJWK(json, xport);
	json["kid"] = getIntName();
	json["x5t"] = BioByteArray(Digest(der, EVP_sha1())).base64UrlEncode();
	json["x5t#256"] = BioByteArray(Digest(der, EVP_sha256())).base64UrlEncode();
	if (xport->match_all(F_JWK_X5C)) {
		QJsonArray x5c;
		for (const pki_x509 *cert = this, *prev = nullptr;
			cert && cert != prev;
			prev = cert, cert = cert->getSigner())
		{
			x5c.append(cert->i2d_b64());
		}
		json["x5c"] = x5c;
	}
	delete key;
}

bool pki_x509::cmpIssuerAndSerial(pki_x509 *refcert)
{
	bool ret =  X509_issuer_and_serial_cmp(cert, refcert->cert);
	pki_openssl_error();
	return ret;
}

bool pki_x509::verify_only(const pki_x509 *signer) const
{
	return X509_check_issued(signer->getCert(), cert) == X509_V_OK;
}

bool pki_x509::verify(pki_x509 *signer)
{
	if (getSigner() || !signer)
		return false;
	if (signer == this &&
	    issuerSqlId == sqlItemId &&
	    issuerSqlId != QVariant())
		return true;

	if (signer && verify_only(signer)) {
		int idx;
		x509rev r;
		x509revList rl(revocation);
		r.setSerial(getSerial());
		setSigner(signer);
		signer->mergeRevList(rl);
		rl = signer->getRevList();
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
	return ::fingerprint(i2d(), digest);
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

pki_x509 *pki_x509::getSigner() const
{
	return Store.lookupPki<pki_x509>(issuerSqlId);
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
			.arg(nativeSeparator(Database.name()))
	);
}

void pki_x509::collect_properties(QMap<QString, QString> &prp) const
{
	prp["Issuer"] = getIssuerName().oneLine(XN_FLAG_RFC2253);
	prp["Serial"] = getSerial().toHex();
	prp["CA"] = isCA() ? "Yes" : "No";
	prp["Not Before"] = getNotBefore().toPretty();
	prp["Not After"] = getNotAfter().toPretty();
	prp["Self signed"] = verify_only(this) ? "Yes" : "No";
	pki_x509super::collect_properties(prp);
}

void pki_x509::print(BioByteArray &bba, enum print_opt opt) const
{
	pki_x509super::print(bba, opt);
	switch (opt) {
	case print_openssl_txt:
		X509_print(bba, cert);
		break;
	case print_pem:
		PEM_write_bio_X509(bba, cert);
		break;
	case print_coloured:
		break;
	}
}

QStringList pki_x509::icsVEVENT_ca() const
{
	QStringList ics;
	pki_crl *crl = NULL;

	ics << icsVEVENT();
	foreach(pki_base *p, childItems) {
		pki_x509 *pki = static_cast<pki_x509 *>(p);
		if (pki->getNotAfter() > a1time() && !isRevoked())
			ics << pki->icsVEVENT();
	}

	QList<pki_crl*> list = Store.sqlSELECTpki<pki_crl>(
		"SELECT item FROM crls WHERE issuer = ?",
		QList<QVariant>() << QVariant(sqlItemId));

	/* Get latest CRL */
	foreach(pki_crl *pki, list) {
		if (!crl || crl->getNextUpdate() < pki->getNextUpdate())
			crl = pki;
	}
	if (crl)
		ics << crl->icsVEVENT();

	return ics;
}

QVariant pki_x509::getIcon(const dbheader *hd) const
{
	int pixnum = 0;
	bool ca;
	QStringList icon_names {
		":validcertIco", ":validcertkeyIco",
		":invalidcertIco", ":invalidcertkeyIco"
	};
	switch (hd->id) {
	case HD_cert_ca:
		if (!caAndPathLen(&ca, NULL, NULL))
			return QVariant();
		if (!ca)
			return QVariant();
		return QVariant(QPixmap(":doneIco"));
	case HD_internal_name:
		if (hasPrivKey())
			pixnum += 1;
		if (isRevoked())
			pixnum += 2;
		break;
	default:
		return pki_x509super::getIcon(hd);
	}
	return QVariant(QPixmap(icon_names[pixnum]));
}

bool pki_x509::unusable() const
{
	return getNotAfter() < a1time::now() || isRevoked();
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
				return QVariant(red);
			break;
		case HD_cert_notAfter: {
			if (na.isUndefined())
				return QVariant(cyan);
			if (na < now)
				return QVariant(red);
			if (certwarn < now)
				return QVariant(yellow);
			break;
		}
		case HD_cert_crl_expire:
			if (canSign()) {
				QDateTime crlwarn, crlex;
				crlex = crlExpire;
				if (!crlExpire.isUndefined()) {
					crlwarn = crlex.addSecs(-2 *60*60*24);
					if (crlex < now)
						return QVariant(red);
					if (crlwarn < now || !crlex.isValid())
						return QVariant(yellow);
				}
			}
	}
	return QVariant();
}

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
	int cert_error = X509_STORE_CTX_get_error(ctx);
	QList<int> *errors = (QList<int>*)X509_STORE_CTX_get_app_data(ctx);

	if (cert_error != X509_V_OK && errors->indexOf(cert_error) == -1)
		errors->append(cert_error);

	qDebug() << "OK:" << ok << "Error:" << cert_error
		<< get_ossl_verify_error(cert_error);
	return 1;
}

QList<int> pki_x509::ossl_verify() const
{
	STACK_OF(X509) *untrusted = sk_X509_new_null();
	Q_CHECK_PTR(untrusted);
	STACK_OF(X509) *trusted = sk_X509_new_null();
	Q_CHECK_PTR(trusted);
	X509_STORE_CTX *csc = X509_STORE_CTX_new();
	Q_CHECK_PTR(csc);

	for (pki_x509 *crt = getSigner(), *oldcrt = nullptr;
		 crt && crt != oldcrt; oldcrt = crt, crt = crt->getSigner())
	{
		if (crt && crt == crt->getSigner())
			sk_X509_push(trusted, crt->getCert());
		else
			sk_X509_push(untrusted, crt->getCert());
	}
	QList<int> errors;
	X509_STORE_CTX_init(csc, NULL, cert, untrusted);
	X509_STORE_CTX_set0_trusted_stack(csc, trusted);
	X509_STORE_CTX_set_verify_cb(csc, verify_cb);
	X509_STORE_CTX_set_app_data(csc, (void *)&errors);

	X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
	Q_CHECK_PTR(param);
	X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_X509_STRICT);
	X509_VERIFY_PARAM_set_depth(param, 20);
	X509_STORE_CTX_set0_param(csc, param);

	qDebug() << "########### START VERIFY" << getIntName();
	int i = X509_verify_cert(csc);
	for (int cert_error : errors) {
		qDebug() << "VERIFY_CB" << getIntName() << cert_error
			<< get_ossl_verify_error(cert_error)
			<< X509_verify_cert_error_string(cert_error);
	}
	qDebug() << "########### END VERIFY" << getIntName() << i;

	X509_STORE_CTX_free(csc);
	sk_X509_free(untrusted);
	sk_X509_free(trusted);

	pki_ign_openssl_error();
	return errors;
}

QList<X509_PURPOSE *> pki_x509::purposes() const
{
	QList<X509_PURPOSE *> purposes;
	for (int i = 0; i< X509_PURPOSE_get_count(); i++) {
		X509_PURPOSE *purp = X509_PURPOSE_get0(i);
		int id = X509_PURPOSE_get_id(purp);
		if (id == X509_PURPOSE_ANY)
			continue;
		Q_CHECK_PTR(purp);
		int r = X509_check_purpose(cert, id, 0);
		qDebug() << "Purpose" << i << X509_PURPOSE_get0_name(purp) << isCA() << r;
		if (r)
			purposes << purp;
	}
	return purposes;
}

int pki_x509::name_constraint_check(pki_x509 *issuer) const
{
	int rc = X509_V_OK;

	if (!issuer || issuer == this)
		return rc;

	x509v3ext e = issuer->getExtByNid(NID_name_constraints);
	if (e.nid() != NID_name_constraints)
		return rc;

	NAME_CONSTRAINTS *nc = (NAME_CONSTRAINTS *)e.d2i();
	Q_CHECK_PTR(nc);
	rc = NAME_CONSTRAINTS_check(cert, nc);
#ifndef LIBRESSL_VERSION_NUMBER
	if (!isCA() && rc == X509_V_OK)
		rc = NAME_CONSTRAINTS_check_CN(cert, nc);
#endif
	NAME_CONSTRAINTS_free(nc);
	pki_openssl_error();
	qDebug() << getIntName() << issuer->getIntName() << get_ossl_verify_error(rc);
	return rc;
}
