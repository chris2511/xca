/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_x509.h"
#include "pki_evp.h"
#include "pki_scard.h"
#include "func.h"
#include "base.h"
#include "exception.h"
#include "pass_info.h"
#include "widgets/MainWindow.h"
#include <QtGui/QMessageBox>
#include <QtCore/QDir>
#include <openssl/rand.h>

bool pki_x509::dont_colorize_expiries = false;
QPixmap *pki_x509::icon[6] = { NULL, NULL, NULL, NULL, NULL, NULL };

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
	trust = crt->trust;
	efftrust = crt->efftrust;
	revoked = crt->revoked;
	caSerial = crt->caSerial;
	caTemplate = crt->caTemplate;
	crlDays = crt->crlDays;
	crlExpiry = crt->crlExpiry;
	isrevoked = isrevoked;
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

QString pki_x509::getMsg(msg_type msg)
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
	/* %1: Number of certs; %2: list of cert ames */
	case msg_delete_multi: return tr("Delete the %1 certificates: %2?");
	}
	return pki_base::getMsg(msg);
}

void pki_x509::fromPEM_BIO(BIO *bio, QString name)
{
	X509 *_cert;
	_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	openssl_error(name);
	X509_free(cert);
	cert = _cert;
	autoIntName();
	if (getIntName().isEmpty())
		setIntName(rmslashdot(name));
	trust = 1;
	efftrust = 1;
}

void pki_x509::fload(const QString fname)
{
	FILE *fp = fopen(QString2filename(fname), "r");
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
	trust = 1;
	efftrust = 1;
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
	trust = 0;
	efftrust = 0;
	revoked = a1time::now();
	caSerial = 1;
	caTemplate = "";
	crlDays = 30;
	crlExpiry = a1time::now();
	class_name = "pki_x509";
	cert = NULL;
	isrevoked = false;
	dataVersion = 3;
	pkiType = x509;
	randomSerial = false;
	revoke_reason = "";
}

void pki_x509::setSerial(const a1int &serial)
{
	if (cert->cert_info->serialNumber != NULL ) {
		ASN1_INTEGER_free(cert->cert_info->serialNumber);
	}
	cert->cert_info->serialNumber = serial.get();
	pki_openssl_error();
}

a1int pki_x509::getSerial() const
{
	a1int a(X509_get_serialNumber(cert));
	return a;
}

#define SERIAL_LEN 8
a1int pki_x509::getIncCaSerial()
{
	unsigned char buf[SERIAL_LEN];
	if (!randomSerial)
		return caSerial++;
	RAND_pseudo_bytes(buf, SERIAL_LEN);
	a1int serial;
	serial.setRaw(buf, SERIAL_LEN);
	return serial;
}

a1int pki_x509::hashInfo(const EVP_MD *md) const
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned len = 0;
	if (!ASN1_item_digest(ASN1_ITEM_rptr(X509_CINF), md,
				(char*)cert->cert_info,digest,&len))
		pki_openssl_error();
	a1int a;
	a.setRaw(digest,len);
	return a;
}

a1int pki_x509::getQASerial(const a1int &secret) const
{
	ASN1_INTEGER *hold = cert->cert_info->serialNumber;
	cert->cert_info->serialNumber = secret.get();
	a1int ret = hashInfo(EVP_md5());
	ASN1_INTEGER_free(cert->cert_info->serialNumber);
	cert->cert_info->serialNumber = hold;
	return ret;
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
		printf("No Cert Label: %s\n", err.getCString());
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
			printf("No Cert Subject: %s\n", err.getCString());
			// IGNORE
		}
	}
	setIntName(desc);
	pki_openssl_error();
}

void pki_x509::d2i(QByteArray &ba)
{
        X509 *c = (X509*)d2i_bytearray(D2I_VOID(d2i_X509), ba);
	if (c) {
		X509_free(cert);
		cert = c;
	}
}

QByteArray pki_x509::i2d()
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
		card = (pki_scard *)privkey;
		if (!card->prepare_card(&slot))
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
		QMessageBox::warning(NULL, XCA_TITLE,
		    tr("This certificate is already on the security token"));
		return;
	}

	p11_atts <<
		pk11_attr_bool(CKA_TOKEN, true) <<
		pk11_attr_bool(CKA_PRIVATE, false) <<
		pk11_attr_data(CKA_SUBJECT, getSubject().i2d()) <<
		pk11_attr_data(CKA_LABEL, desc.toUtf8()) <<
		(card ? card->getIdAttr() : p11.findUniqueID(CKO_CERTIFICATE));

	if (p11.tokenLogin(p11.tokenInfo().label(), false).isNull())
		return;

	p11.createObject(p11_atts);
}

void pki_x509::deleteFromToken()
{
	pki_scard *card = (pki_scard *)privkey;
	slotidList p11_slots;

	if (!pkcs11::loaded())
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
	if (QMessageBox::question(NULL, XCA_TITLE,
		tr("Delete the certificate '%1' from the token '%2 (#%3)'?").
		arg(getIntName()).arg(ti.label()).arg(ti.serial()),
		QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
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

bool pki_x509::verifyQASerial(const a1int &secret) const
{
	return getQASerial(secret) == getSerial();
}

void pki_x509::setNotBefore(const a1time &a)
{
	a1time t(a);
	X509_set_notBefore(cert, t.get_utc());
}

void pki_x509::setNotAfter(const a1time &a)
{
	a1time t(a);
	X509_set_notAfter(cert, t.get_utc());
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
	x509name x(cert->cert_info->subject);
	pki_openssl_error();
	return x;
}

x509name pki_x509::getIssuer() const
{
	x509name x(cert->cert_info->issuer);
	pki_openssl_error();
	return x;
}

void pki_x509::setSubject(const x509name &n)
{
	if (cert->cert_info->subject != NULL)
		X509_NAME_free(cert->cert_info->subject);
	cert->cert_info->subject = n.get();
}

void pki_x509::setIssuer(const x509name &n)
{
	if ((cert->cert_info->issuer) != NULL)
		X509_NAME_free(cert->cert_info->issuer);
	cert->cert_info->issuer = n.get();
}

void pki_x509::addV3ext(const x509v3ext &e)
{
	if (!e.isValid()) return;
	X509_EXTENSION *ext = e.get();
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	pki_openssl_error();
}

void pki_x509::delSigner(pki_base *s)
{
	if (s == psigner)
		psigner = NULL;
}

bool pki_x509::canSign()
{
	BASIC_CONSTRAINTS *bc;
	int crit;
	if (!privkey || privkey->isPubKey())
		return false;
	if (privkey->isToken() && !pkcs11::loaded())
		return false;
	bc = (BASIC_CONSTRAINTS *)X509_get_ext_d2i(cert, NID_basic_constraints, &crit, NULL);
	pki_openssl_error();
	if (!bc || !bc->ca)
		return false;
	return true;
}

bool pki_x509::hasExtension(int nid)
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

	version = head->version;
	size = head->len - sizeof(db_header_t);

	QByteArray ba((const char*)p, size);

	d2i(ba);
	trust = db::intFromData(ba);
	isrevoked = db::boolFromData(ba);
	revoked.d2i(ba);
	caSerial.setHex(db::stringFromData(ba));
	caTemplate = db::stringFromData(ba);
	crlDays = db::intFromData(ba);
	crlExpiry.d2i(ba);
	if (version > 1)
		randomSerial = db::boolFromData(ba);
	else
		randomSerial = false;
	if (version > 2) {
		crlNumber.setHex(db::stringFromData(ba));
		revoke_reason = db::stringFromData(ba);
		invalDate.d2i(ba);
	}
	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}


QByteArray pki_x509::toData()
{
	QByteArray ba;

	ba += i2d(); // cert
	ba += db::intToData(trust);
	ba += db::boolToData(isrevoked);
	ba += revoked.i2d(); // revokation date

	// the serial if this is a CA
	ba += db::stringToData(caSerial.toHex());
	// the name of the template to use for signing
	ba += db::stringToData(caTemplate);
	// version 3
	ba += db::intToData(crlDays); // the CRL period
	ba += crlExpiry.i2d(); // last CRL date
	ba += db::boolToData(randomSerial);
	ba += db::stringToData(crlNumber.toHex());
	ba += db::stringToData(revoke_reason);
	ba += invalDate.i2d();
	pki_openssl_error();
	return ba;
}

void pki_x509::writeDefault(const QString fname)
{
	writeCert(fname + QDir::separator() + getIntName() + ".crt",
			true, false);
}

void pki_x509::writeCert(const QString fname, bool PEM, bool append)
{
	FILE *fp;
	const char *p = "w";
	if (append)
		p = "a";
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

BIO *pki_x509::pem(BIO *b)
{
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

bool pki_x509::verify(pki_x509 *signer)
{
	if (psigner == signer)
		return true;
	if ((psigner != NULL )||( signer == NULL))
		return false;
	X509_NAME *subject =  X509_get_subject_name(signer->cert);
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
	if (i>0) {
		psigner = signer;
		return true;
	}
	return false;
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

void pki_x509::setPubKey(pki_key *key)
{
	 X509_set_pubkey(cert, key->getPubKey());
}

QString pki_x509::fingerprint(const EVP_MD *digest)
{
	int j;
	QString fp="";
	char zs[4];
	unsigned int n;
	unsigned char md[EVP_MAX_MD_SIZE];
	X509_digest(cert, digest, md, &n);
	pki_openssl_error();
	for (j=0; j<(int)n; j++) {
		sprintf(zs, "%02X%c",md[j], (j+1 == (int)n) ?'\0':':');
		fp += zs;
	}
	return fp;
}

bool pki_x509::checkDate()
{
	a1time n, b, a;

	n = a1time::now(),
	b = getNotBefore();
	a = getNotAfter();

	if (!a.isValid() || !b.isValid())
		return false;
	if (!a.isUndefined() && (a < n))
		return false;
	if (b > n)
		return false;
	pki_openssl_error();
	return true;
}

extList pki_x509::getV3ext()
{
	extList el;
	el.setStack(cert->cert_info->extensions);
	return el;
}

x509v3ext pki_x509::getExtByNid(int nid)
{
	extList el = getV3ext();
	int i = el.idxByNid(nid);

	if (i == -1)
		return x509v3ext();
	return el[i];
}

pki_x509 *pki_x509::getSigner()
{
	return (pki_x509 *)psigner;
}

int pki_x509::getTrust()
{
	if (trust > 2) trust = 2;
	if (trust < 0) trust = 0;
	return trust;
}

void pki_x509::setTrust(int t)
{
	if (t>=0 && t<=2)
		trust = t;
}

int pki_x509::getEffTrust()
{
	if (efftrust > 2) efftrust = 2;
	if (efftrust < 0) efftrust = 0;
	return efftrust;
}

void pki_x509::setEffTrust(int t)
{
	if (t>= 0 && t<= 2)
		efftrust = t;
}

bool pki_x509::isRevoked()
{
	return isrevoked ;
}

void pki_x509::setRevoked(bool rev, a1time inval, QString reason)
{
	if (rev) {
		setEffTrust(0);
		revoked = a1time::now();
		pki_openssl_error();
		revoke_reason = reason;
		invalDate = inval;
	}
	isrevoked = rev;
	pki_openssl_error();
}

a1time &pki_x509::getRevoked()
{
	return revoked;
}

void pki_x509::setRevoked(const a1time &when)
{
	isrevoked = true;
	revoked = when;
	setEffTrust(0);
	setTrust(0);
	pki_openssl_error();
}

int pki_x509::calcEffTrust()
{
	int mytrust = trust;
	if (mytrust != 1) {
		efftrust = mytrust;
		return mytrust;
	}
	if (isRevoked()) {
		efftrust = 0;
		return 0;
	}
	if (getSigner() == this && trust == 1) { // inherit trust, but self signed
		trust=0;
		efftrust=0;
		return 0;
	}
	//we must look at the parent certs
	pki_x509 *signer = getSigner();
	while (mytrust == 1 && signer && signer != this) {
		mytrust = signer->getTrust();
		signer = signer->getSigner();
	}

	if (mytrust == 1) mytrust = 0;
	efftrust = mytrust;
	return mytrust;
}

void pki_x509::setCrlExpiry(const a1time &time)
{
	crlExpiry = time;
	pki_openssl_error();
}

x509rev pki_x509::getRev(bool reason)
{
	x509rev a;
	a.setDate(getRevoked());
	a.setSerial(getSerial());
	if (reason) {
		a.setReason(revoke_reason);
		a.setInvalDate(invalDate);
	}
	return a;
}

bool pki_x509::caAndPathLen(bool *ca, a1int *pathlen, bool *hasLen)
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
	return true;
}

QVariant pki_x509::column_data(dbheader *hd)
{
	QString truststatus[] =
		{ tr("Not trusted"), tr("Trust inherited"), tr("Always Trusted") };

	switch (hd->id) {
		case HD_cert_serial:
			return QVariant(getSerial().toHex());
		case HD_cert_notBefore:
			return QVariant(getNotBefore().toSortable());
		case HD_cert_notAfter:
			return QVariant(getNotAfter().toSortable());
		case HD_cert_trust:
			return QVariant(truststatus[getTrust()]);
		case HD_cert_revokation:
			if (isRevoked())
				return QVariant(getRevoked().toSortable());
			else if (canSign())
				return QVariant(tr("CRL expires: %1").
					arg(crlExpiry.toSortable()));
			return QVariant();
		case HD_cert_md5fp:
			return QVariant(fingerprint(EVP_md5()));
		case HD_cert_sha1fp:
			return QVariant(fingerprint(EVP_sha1()));
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
			return QVariant("");
		}
	}
	return pki_x509super::column_data(hd);
}

QVariant pki_x509::getIcon(dbheader *hd)
{
	int pixnum = 0;
	bool ca;
	pki_key *k;

	switch (hd->id) {
	case HD_cert_ca:
		if (!caAndPathLen(&ca, NULL, NULL))
			return QVariant();
		if (!ca)
			return QVariant();
		pixnum = 5;
		break;
	case HD_internal_name:
		k = getRefKey();
		if (k && k->isPrivKey()) {
			pixnum += 1;
		}
		if (calcEffTrust() == 0){
			pixnum += 2;
		}
		break;
	default:
		return QVariant();
	}
	return QVariant(*icon[pixnum]);
}

QString pki_x509::getSigAlg()
{
	QString alg = OBJ_nid2ln(OBJ_obj2nid(cert->sig_alg->algorithm));
	return alg;
}

const EVP_MD *pki_x509::getDigest()
{
	return EVP_get_digestbyobj(cert->sig_alg->algorithm);
}

QVariant pki_x509::bg_color(dbheader *hd)
{
#define BG_RED     QBrush(QColor(255,  0,  0))
#define BG_YELLOW  QBrush(QColor(255,255,  0))
#define BG_CYAN    QBrush(QColor(127,255,212))

	if (dont_colorize_expiries)
		return QVariant();

	a1time nb, na, now, certwarn;

	nb = getNotBefore();
	na = getNotAfter();
	now = a1time::now();

	int lifetime = nb.secsTo(na);

	/* warn after 4/5 certificate lifetime */
	certwarn = na.addSecs(- lifetime /5);

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
		case HD_cert_revokation:
			if (canSign()) {
				QDateTime crlwarn, crlex;
				crlex = crlExpiry;
				crlwarn = crlex.addSecs(-2 *60*60*24);
				if (crlex < now)
					return QVariant(BG_RED);
				if (crlwarn < now || !crlex.isValid())
					return QVariant(BG_YELLOW);
			}
	}
	return QVariant();
}

void pki_x509::oldFromData(unsigned char *p, int size)
{
	int version, sRev, sLastCrl;
	QByteArray ba((char*)p, size);
	X509 *cert_sik = cert;
	cert = NULL;
	version = intFromData(ba);
	if (version >=1 && version <= 5) {
		intFromData(ba); /* sCert */
		d2i(ba);
		trust = intFromData(ba);
		sRev = intFromData(ba);
		if (sRev) {
			if (version != 3) isrevoked = true;
			revoked.d2i(ba);
		}
		else {
			isrevoked = false;
			revoked = a1time::now();
		}

		if (version == 1) {
			caTemplate="";
			caSerial=1;
			crlExpiry=a1time::now();
			crlDays=30;
		}

		if (version >= 2 ) {
			if (version >= 5)
				caSerial.setHex(db::stringFromData(ba));
			else {
				int i = intFromData(ba);
				if (i>=0)
					caSerial = i;
				else {
					caSerial = getSerial();
					++caSerial;
				}
			}
			caTemplate = db::stringFromData(ba);
		}
		if (version >= 3 ) {
			crlDays = intFromData(ba);
			sLastCrl = intFromData(ba);
			if (sLastCrl) {
			   crlExpiry.d2i(ba);
			}
		}
		// version 4 saves a NULL as revoked
		// version 3 did save a recent date :-((
	}
	else { // old version
		d2i(ba);
		revoked = NULL;
		trust = 1;
		efftrust = 1;
	}
	if (cert)
		X509_free(cert_sik);
	else
		cert = cert_sik;

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}

