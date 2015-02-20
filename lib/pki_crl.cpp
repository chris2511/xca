/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_crl.h"
#include "func.h"
#include "exception.h"
#include <QDir>

QPixmap *pki_crl::icon = NULL;

pki_crl::pki_crl(const QString name )
	:pki_x509name(name)
{
	issuer = NULL;
	crl = X509_CRL_new();
	class_name="pki_crl";
	pki_openssl_error();
	dataVersion=1;
	pkiType=revocation;
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

QString pki_crl::getMsg(msg_type msg)
{
	/*
	 * We do not construct english sentences from fragments
	 * to allow proper translations.
	 *
	 * %1 will be replaced by the internal name of the CRL
	 */
	switch (msg) {
	case msg_import: return tr("Successfully imported the revocation list '%1'");
	case msg_delete: return tr("Delete the revocation list '%1'?");
	case msg_create: return tr("Successfully created the revocation list '%1'");
	/* %1: Number of CRLs; %2: list of CRL names */
	case msg_delete_multi: return tr("Delete the %1 revocation lists: %2?");
	}
	return pki_base::getMsg(msg);
}

void pki_crl::fload(const QString fname)
{
	FILE *fp = fopen_read(fname);
	X509_CRL *_crl;
	if (fp != NULL) {
		_crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
		if (!_crl) {
			pki_ign_openssl_error();
			rewind(fp);
			_crl = d2i_X509_CRL_fp(fp, NULL);
		}
		fclose(fp);
		if (pki_ign_openssl_error()) {
			if (_crl)
				X509_CRL_free(_crl);
			throw errorEx(tr("Unable to load the revocation list in file %1. Tried PEM and DER formatted CRL.").arg(fname));
		}
		if (crl)
			X509_CRL_free(crl);
		crl = _crl;
		setIntName(rmslashdot(fname));
		pki_openssl_error();
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
	a1int version = 1; /* version 2 CRL */
	crl->crl->version = version.get();
	pki_openssl_error();
}

a1int pki_crl::getVersion()
{
	a1int a(crl->crl->version);
	return a;
}

void pki_crl::setLastUpdate(const a1time &a)
{
	a1time t(a);
	X509_CRL_set_lastUpdate(crl, t.get_utc());
}

void pki_crl::setNextUpdate(const a1time &a)
{
	a1time t(a);
	X509_CRL_set_nextUpdate(crl, t.get_utc());
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
	int size;

	size = head->len - sizeof(db_header_t);

	QByteArray ba((const char*)p, size);
	d2i(ba);

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}

QByteArray pki_crl::toData()
{
	QByteArray ba = i2d();
	pki_openssl_error();
	return ba;
}

void pki_crl::addRev(const x509rev &xrev, bool withReason)
{
	X509_CRL_add0_revoked(crl, xrev.get(withReason));
	pki_openssl_error();
}

void pki_crl::addV3ext(const x509v3ext &e)
{
	X509_EXTENSION *ext = e.get();
	X509_CRL_add_ext(crl, ext, -1);
	X509_EXTENSION_free(ext);
	pki_openssl_error();
}

bool pki_crl::visible()
{
	extList el;
	if (pki_x509name::visible())
		return true;
	if (getSigAlg().contains(limitPattern))
		return true;
	el.setStack(crl->crl->extensions);
	return el.search(limitPattern);
}

void pki_crl::sign(pki_key *key, const EVP_MD *md)
{
	EVP_PKEY *pkey;
	if (!key || key->isPubKey())
		return;
	X509_CRL_sort(crl);
	pkey = key->decryptKey();
	X509_CRL_sign(crl, pkey, md);
	EVP_PKEY_free(pkey);
	pki_openssl_error();
}

void pki_crl::writeDefault(const QString fname)
{
	writeCrl(fname + QDir::separator() + getUnderlinedName() + ".crl", true);
}

void pki_crl::writeCrl(const QString fname, bool pem)
{
	FILE *fp = fopen_write(fname);
	if (fp != NULL) {
		if (crl){
			if (pem)
				PEM_write_X509_CRL(fp, crl);
			else
				i2d_X509_CRL_fp(fp, crl);
		}
		fclose(fp);
		pki_openssl_error();
	} else
		fopen_error(fname);
}

BIO *pki_crl::pem(BIO *b, int format)
{
	(void)format;
	if (!b)
		b = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_CRL(b, crl);
	return b;
}

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
	return 0;
}

x509revList pki_crl::getRevList()
{
	x509revList ret;
	int i, num = numRev();

	for (i=0; i<num; i++) {
		x509rev r(sk_X509_REVOKED_value(crl->crl->revoked, i));
		pki_openssl_error();
		ret << r;
	}
	return ret;
}

x509name pki_crl::getSubject() const
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
		ret = (X509_CRL_verify(crl, key->getPubKey()) == 1);
		pki_ign_openssl_error();
	}
	return ret;
}

void pki_crl::setCrlNumber(a1int num)
{
	ASN1_INTEGER *tmpser = num.get();
	pki_openssl_error();
	X509_CRL_add1_ext_i2d(crl, NID_crl_number, tmpser, 0, 0);
	ASN1_INTEGER_free(tmpser);
	pki_openssl_error();
}

a1int pki_crl::getCrlNumber()
{
	a1int num;
	if (!getCrlNumber(&num))
		num.set(0L);
	return num;
}

bool pki_crl::getCrlNumber(a1int *num)
{
	int j;
	ASN1_INTEGER *i;
	i = (ASN1_INTEGER *)X509_CRL_get_ext_d2i(crl, NID_crl_number, &j, NULL);
	pki_openssl_error();
	if (j == -1)
		return false;
	num->set(i);
	ASN1_INTEGER_free(i);
	return true;
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
	pki_openssl_error();
	return text;
}

QVariant pki_crl::column_data(dbheader *hd)
{
	switch (hd->id) {
		case HD_crl_signer:
			if (issuer)
				return QVariant(getIssuer()->getIntName());
			else
				return QVariant(tr("unknown"));
		case HD_crl_revoked:
			return QVariant(numRev());
		case HD_crl_lastUpdate:
			return QVariant(getLastUpdate().toSortable());
		case HD_crl_nextUpdate:
			return QVariant(getNextUpdate().toSortable());
		case HD_crl_crlnumber:
			a1int a;
			if (getCrlNumber(&a))
				return QVariant(a.toDec());
			return QVariant();
	}
	return pki_x509name::column_data(hd);
}

QVariant pki_crl::getIcon(dbheader *hd)
{
	return hd->id == HD_internal_name ? QVariant(*icon) : QVariant();
}

void pki_crl::oldFromData(unsigned char *p, int size)
{
	QByteArray ba((const char *)p, size);
	d2i(ba);

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}
