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

bool pki_key::isScard()
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

bool pki_key::compare(pki_base *ref)
{
	pki_key *kref = (pki_key *)ref;
	if (kref->getKeyType() != getKeyType())
		return false;
	if (!kref || !kref->key || !key)
		return false;
	switch (key->type) {
	case EVP_PKEY_RSA:
		if (!kref->key->pkey.rsa->n || !key->pkey.rsa->n)
			return false;
		if (BN_cmp(key->pkey.rsa->n, kref->key->pkey.rsa->n) ||
		    BN_cmp(key->pkey.rsa->e, kref->key->pkey.rsa->e))
		{
			openssl_error();
			return false;
		}
		break;
	case EVP_PKEY_DSA:
		if (!kref->key->pkey.dsa->pub_key || !key->pkey.dsa->pub_key)
			return false;
		if (BN_cmp(key->pkey.dsa->pub_key,
			   kref->key->pkey.dsa->pub_key))
		{
			openssl_error();
			return false;
		}
		break;
	case EVP_PKEY_EC:
		EC_KEY *ec = key->pkey.ec, *ec_ref = kref->key->pkey.ec;
		const EC_GROUP *group = EC_KEY_get0_group(ec);

		if (!ec || !ec_ref)
			return false;
		if (EC_GROUP_cmp(EC_KEY_get0_group(ec), group, NULL))
			return false;
		openssl_error();
		if (EC_POINT_cmp(group, EC_KEY_get0_public_key(ec),
				 EC_KEY_get0_public_key(ec_ref), NULL))
			return false;
		if (ign_openssl_error())
			return false;
	}
	openssl_error();
	return true;
}

int pki_key::getKeyType()
{
	return key->type;
}

void pki_key::writePublic(const QString fname, bool pem)
{
	FILE *fp = fopen(fname.toAscii(),"w");
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

QString pki_key::BN2QString(BIGNUM *bn)
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

