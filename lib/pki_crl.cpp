/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_crl.h"
#include "func.h"
#include "exception.h"
#include <qdir.h>

QPixmap *pki_crl::icon = NULL;

pki_crl::pki_crl(const QString name )
	:pki_base(name)
{
	issuer = NULL;
	crl = X509_CRL_new();
	class_name="pki_crl";
	openssl_error();
	dataVersion=1;
	pkiType=revokation;
	cols=3;
}

void pki_crl::fromPEM_BIO(BIO *bio, QString name)
{
	X509_CRL*_crl;
	_crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
	openssl_error(name);
	X509_CRL_free(crl);
	crl = _crl;
	setIntName(rmslashdot(name));
}

QString pki_crl::getFriendlyClassName()
{
	return tr("certificate revokation list");
}

void pki_crl::fload(const QString fname)
{
	FILE *fp = fopen(QString2filename(fname), "r");
	X509_CRL *_crl;
	if (fp != NULL) {
		_crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
		if (!_crl) {
			ign_openssl_error();
			rewind(fp);
			_crl = d2i_X509_CRL_fp(fp, NULL);
		}
		fclose(fp);
		if (ign_openssl_error()) {
			if (_crl)
				X509_CRL_free(_crl);
			throw errorEx(tr("Unable to load the revokation list in file %1. Tried PEM and DER formatted CRL.").arg(fname));
		}
		if (crl)
			X509_CRL_free(crl);
		crl = _crl;
		setIntName(rmslashdot(fname));
		openssl_error(fname);
	} else
		fopen_error(fname);
}

QString pki_crl::getSigAlg()
{
	QString alg = OBJ_nid2ln(OBJ_obj2nid(crl->sig_alg->algorithm));
	return alg;
}

void pki_crl::createCrl(const QString d, pki_x509 *iss )
{
	setIntName(d);
	issuer = iss;
	if (!iss)
		my_error(tr("No issuer given"));
	crl->crl->issuer = issuer->getSubject().get();
	crl->crl->revoked = sk_X509_REVOKED_new_null();
	a1int version = 1; /* version 2 CRL */
	crl->crl->version = version.get();
	openssl_error();
}

a1int pki_crl::getVersion()
{
	a1int a(crl->crl->version);
	return a;
}

void pki_crl::setLastUpdate(const a1time &t)
{
	if (crl->crl->lastUpdate != NULL)
		ASN1_TIME_free(crl->crl->lastUpdate);

	crl->crl->lastUpdate = t.get_utc();
}

void pki_crl::setNextUpdate(const a1time &t)
{
	if (crl->crl->nextUpdate != NULL)
		ASN1_TIME_free(crl->crl->nextUpdate);

	crl->crl->nextUpdate = t.get_utc();
}

pki_crl::~pki_crl()
{
	X509_CRL_free(crl);
}

void pki_crl::d2i(QByteArray &ba)
{
	X509_CRL *c = (X509_CRL*)d2i_bytearray(D2I_VOID(d2i_X509_CRL), ba);
	if (c) {
		X509_CRL_free(crl);
		crl = c;
	}
}

QByteArray pki_crl::i2d()
{
	return i2d_bytearray(I2D_VOID(i2d_X509_CRL), crl);
}

void pki_crl::fromData(const unsigned char *p, db_header_t *head)
{
	int version, size;

	size = head->len - sizeof(db_header_t);
	version = head->version;

	QByteArray ba((const char*)p, size);
	d2i(ba);

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}

QByteArray pki_crl::toData()
{
	QByteArray ba = i2d();
	openssl_error();
	return ba;
}

bool pki_crl::compare(pki_base *refcrl)
{
	bool ret;
	ret = X509_CRL_cmp(crl, ((pki_crl *)refcrl)->crl) == 0 &&
		getLastUpdate() == ((pki_crl *)refcrl)->getLastUpdate() &&
		getNextUpdate() == ((pki_crl *)refcrl)->getNextUpdate() ;
	openssl_error();
	return ret;
}


void pki_crl::addRev(const x509rev &xrev)
{
	sk_X509_REVOKED_push(crl->crl->revoked, xrev.get());
	openssl_error();
}

void pki_crl::addV3ext(const x509v3ext &e)
{
	X509_EXTENSION *ext = e.get();
	X509_CRL_add_ext(crl, ext, -1);
	X509_EXTENSION_free(ext);
	openssl_error();
}


void pki_crl::sign(pki_key *key, const EVP_MD *md)
{
	EVP_PKEY *pkey;
	if (!key || key->isPubKey())
		return;
	pkey = key->decryptKey();
	X509_CRL_sign(crl, pkey, md);
	EVP_PKEY_free(pkey);
	openssl_error();
}

void pki_crl::writeDefault(const QString fname)
{
	writeCrl(fname + QDir::separator() + getUnderlinedName() + ".crl", true);
}

void pki_crl::writeCrl(const QString fname, bool pem)
{
	FILE *fp = fopen(QString2filename(fname), "w");
	if (fp != NULL) {
		if (crl){
			if (pem)
				PEM_write_X509_CRL(fp, crl);
			else
				i2d_X509_CRL_fp(fp, crl);
		}
		fclose(fp);
		openssl_error();
	} else
		fopen_error(fname);
}

pki_x509 *pki_crl::getIssuer() { return issuer; }
void pki_crl::setIssuer(pki_x509 *iss) { issuer = iss; }


a1time pki_crl::getLastUpdate()
{
	a1time a;
	if (crl && crl->crl)
		a.set(crl->crl->lastUpdate);
	return a;
}

a1time pki_crl::getNextUpdate()
{
	a1time a;
	if (crl && crl->crl)
		a.set(crl->crl->nextUpdate);
	return a;
}

int pki_crl::numRev()
{
	if (crl && crl->crl && crl->crl->revoked)
		return sk_X509_REVOKED_num(crl->crl->revoked);
	else
		return 0;
}

x509rev pki_crl::getRev(int num)
{
	x509rev ret;
	if (crl && crl->crl && crl->crl->revoked) {
		ret.set(sk_X509_REVOKED_value(crl->crl->revoked, num));
		openssl_error();
	}
	return ret;
}

x509name pki_crl::getIssuerName()
{
	x509name x;
	if (crl && crl->crl && crl->crl->issuer) {
		x.set(crl->crl->issuer);
	}
	return x ;
}

bool pki_crl::verify(pki_key *key)
{
	bool ret=false;
	if (crl && crl->crl && key) {
		ret = (X509_CRL_verify(crl , key->getPubKey()) == 1);
		ign_openssl_error();
	}
	return ret ;
}

x509v3ext pki_crl::getExtByNid(int nid)
{
	extList el;
	x509v3ext e;
	el.setStack(crl->crl->extensions);

	for (int i=0; i< el.count(); i++){
		if (el[i].nid() == nid) return el[i];
	}
	return e;
}

QString pki_crl::printV3ext()
{
	extList el;
	el.setStack(crl->crl->extensions);
	QString text = el.getHtml("<br>");
	openssl_error();
	return text;
}

QVariant pki_crl::column_data(int col)
{
	switch (col) {
		case 0:
			return QVariant(getIntName());
		case 1:
			if (issuer)
				return QVariant(getIssuer()->getIntName());
			else
				 return QVariant(tr("unknown"));
		case 2:
			return QVariant(getIssuerName().getEntryByNid(NID_commonName));
		case 3:
			return QVariant(numRev());
		case 4:
			return QVariant(getNextUpdate().toSortable());
	}
	return QVariant();
}

QVariant pki_crl::getIcon(int column)
{
	return column == 0 ? QVariant(*icon) : QVariant();
}

void pki_crl::oldFromData(unsigned char *p, int size)
{
	QByteArray ba((const char *)p, size);
	d2i(ba);

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}
