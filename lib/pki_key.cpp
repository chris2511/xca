/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_key.h"
#include "func.h"
#include "db.h"
#include <qapplication.h>
#include <widgets/MainWindow.h>

pki_key::pki_key(const QString name)
        :pki_base(name)
{
	key = EVP_PKEY_new();
	ucount = 0;
	class_name = "pki_key";
}

pki_key::pki_key(const pki_key *pk)
	:pki_base(pk->desc)
{
	int keylen;
	unsigned char *der_key, *p;

	ucount = pk->ucount;

	keylen = i2d_PUBKEY(pk->key, NULL);
	p = der_key = (unsigned char *)OPENSSL_malloc(keylen);
	check_oom(der_key);
	i2d_PUBKEY(pk->key, &p);
	p = der_key;
	key = d2i_PUBKEY(NULL, (const unsigned char**)&p, keylen);
	OPENSSL_free(der_key);
	openssl_error();
}

pki_key::~pki_key()
{
	if (key)
		EVP_PKEY_free(key);
}

QString pki_key::getTypeString()
{
	QString type;
	switch (EVP_PKEY_type(key->type)) {
		case EVP_PKEY_RSA:
			type = "RSA";
			break;
		case EVP_PKEY_DSA:
			type = "DSA";
			break;
		case EVP_PKEY_EC:
			type = "EC";
			break;
		default:
			type = "---";
	}
	return type;
}

QString pki_key::getFriendlyClassName()
{
	QString txt = isPubKey() ? tr("%1 public key") : tr("%1 private key");
	return txt.arg(getTypeString());
}

QString pki_key::getIntNameWithType()
{
	return getIntName() + " (" + getTypeString() + ")";
}

QString pki_key::removeTypeFromIntName(QString n)
{
	int i;
	if (n.right(1) != ")" )
		return n;
	i = n.lastIndexOf(" (");
	if (i > 0)
		n.truncate(i);
	return n;
}

bool pki_key::isToken()
{
	return false;
}

bool pki_key::isPrivKey() const
{
	return !isPubKey();
}

int pki_key::incUcount()
{
	ucount++;
	return ucount;
}
int pki_key::decUcount()
{
	ucount--;
	return ucount;
}

int pki_key::getUcount()
{
	return ucount;
}

int pki_key::getKeyType()
{
	return key->type;
}

QString pki_key::modulus()
{
	if (key->type == EVP_PKEY_RSA)
		return BN2QString(key->pkey.rsa->n);
	return QString();
}

QString pki_key::pubEx()
{
	if (key->type == EVP_PKEY_RSA)
		return BN2QString(key->pkey.rsa->e);
	return QString();
}

QString pki_key::subprime()
{
	if (key->type == EVP_PKEY_DSA)
		return BN2QString(key->pkey.dsa->q);
	return QString();
}

QString pki_key::pubkey()
{
	if (key->type == EVP_PKEY_DSA)
		return BN2QString(key->pkey.dsa->pub_key);
	return QString();
}

int pki_key::ecParamNid()
{
	if (key->type != EVP_PKEY_EC)
		return 0;
	return EC_GROUP_get_curve_name(EC_KEY_get0_group(key->pkey.ec));
}

QString pki_key::ecPubKey()
{
	QString pub;
	if (key->type == EVP_PKEY_EC) {
		EC_KEY *ec = key->pkey.ec;
		BIGNUM  *pub_key = EC_POINT_point2bn(EC_KEY_get0_group(ec),
				EC_KEY_get0_public_key(ec),
				EC_KEY_get_conv_form(ec), NULL, NULL);
		if (pub_key) {
			pub = BN2QString(pub_key);
			BN_free(pub_key);
		}
	}
	return pub;
}

bool pki_key::compare(pki_base *ref)
{
	pki_key *kref = (pki_key *)ref;

	if (kref->getKeyType() != getKeyType())
		return false;
	if (!kref || !kref->key || !key)
		return false;

	int r = EVP_PKEY_cmp(key, kref->key);
	openssl_error();
	return r == 1;
}

void pki_key::writePublic(const QString fname, bool pem)
{
	FILE *fp = fopen(QString2filename(fname), "w");
	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	if (pem)
		PEM_write_PUBKEY(fp, key);
	else
		i2d_PUBKEY_fp(fp, key);

	fclose(fp);
	openssl_error();
}

QString pki_key::BNoneLine(BIGNUM *bn) const
{
	QString x;
	if (bn) {
		char *hex = BN_bn2hex(bn);
		x = hex;
		OPENSSL_free(hex);
		openssl_error();
	}
	return x;
}

QString pki_key::BN2QString(BIGNUM *bn) const
{
	if (bn == NULL)
		return "--";
	QString x="";
	char zs[10];
	int j;
	int size = BN_num_bytes(bn);
	unsigned char *buf = (unsigned char *)OPENSSL_malloc(size);
	check_oom(buf);
	BN_bn2bin(bn, buf);
	for (j = 0; j< size; j++) {
		sprintf(zs, "%02X%c",buf[j], ((j+1)%16 == 0) ? '\n' :
				j<size-1 ? ':' : ' ');
		x += zs;
	}
	OPENSSL_free(buf);
	openssl_error();
	return x;
}

QVariant pki_key::column_data(int col)
{
	QStringList sl;
	sl << tr("Common") << tr("Private") << tr("Bogus") << tr("PIN");
	switch (col) {
		case 0:
			return QVariant(getIntName());
		case 1:
			return QVariant(getTypeString());
		case 2:
			return QVariant(length());
		case 3:
			return QVariant(getUcount());
		case 4:
			if (isPubKey())
				return QVariant(tr("No password"));
			if (ownPass<0 || ownPass>3)
				return QVariant("Holla die Waldfee");
			return QVariant(sl[ownPass]);
	}
	return QVariant();
}

