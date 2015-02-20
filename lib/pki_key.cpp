/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_key.h"
#include "func.h"
#include "db.h"
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <QProgressDialog>
#include <QApplication>
#include <QDir>
#include "widgets/PwDialog.h"

builtin_curves pki_key::builtinCurves;

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
	ucount = pk->ucount;
	key = EVP_PKEY_new();
	if (pk->key) {
		QByteArray ba = i2d_bytearray(I2D_VOID(i2d_PUBKEY), pk->key);
		d2i(ba);
	}
}

pki_key::~pki_key()
{
	if (key)
		EVP_PKEY_free(key);
}

void pki_key::d2i(QByteArray &ba)
{
	EVP_PKEY *k = (EVP_PKEY*)d2i_bytearray(D2I_VOID(d2i_PUBKEY), ba);
        pki_openssl_error();
	if (k) {
		if (key)
			EVP_PKEY_free(key);
		key = k;
	}
}

void pki_key::d2i_old(QByteArray &ba, int type)
{
	const unsigned char *p, *p1;
	p = p1 = (const unsigned char *)ba.constData();
	EVP_PKEY *k = d2i_PublicKey(type, NULL, &p1, ba.count());

        pki_openssl_error();

	if (k) {
		if (key)
			EVP_PKEY_free(key);
		key = k;
	}
        ba = ba.mid(p1-p);
}

QByteArray pki_key::i2d()
{
        return i2d_bytearray(I2D_VOID(i2d_PUBKEY), key);
}

BIO *pki_key::pem(BIO *b, int format)
{
	EVP_PKEY *pkey;
	QByteArray ba;
	if (!b)
		b = BIO_new(BIO_s_mem());

	switch (format) {
	case exportType::SSH2_public:
		ba = SSH2publicQByteArray();
		BIO_write(b, ba.data(), ba.size());
		break;
	case exportType::PEM_private:
		pkey = decryptKey();
		PEM_write_bio_PrivateKey(b, pkey, NULL, NULL, 0, NULL, NULL);
		EVP_PKEY_free(pkey);
		break;
	case exportType::PEM_key:
		PEM_write_bio_PUBKEY(b, key);
		break;
	}
	return b;
}

QString pki_key::length()
{
	if (key->type == EVP_PKEY_DSA && key->pkey.dsa->p == NULL) {
		return QString("???");
	}
	return QString("%1 bit").arg(EVP_PKEY_bits(key));
}

QString pki_key::getTypeString() const
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

QString pki_key::getMsg(msg_type msg)
{
	/*
	 * We do not construct english sentences (just a little bit)
	 * from fragments to allow proper translations.
	 * The drawback are all the slightly different duplicated messages
	 *
	 * %1 will be replaced by "RSA", "DSA", "EC"
	 * %2 is the internal name of the key
	 */
	QString ktype = getTypeString();
	if (isPubKey()) {
		switch (msg) {
		case msg_import: return tr("Successfully imported the %1 public key '%2'").arg(ktype);
		case msg_delete: return tr("Delete the %1 public key '%2'?").arg(ktype);
		default: break;
		}
	} else {
		switch (msg) {
		case msg_import: return tr("Successfully imported the %1 private key '%2'").arg(ktype);
		case msg_delete: return tr("Delete the %1 private key '%2'?").arg(ktype);
		case msg_create: return tr("Successfully created the %1 private key '%2'").arg(ktype);
		default: break;
		}
	}
	if (msg == msg_delete_multi) {
		/* %1: Number of keys; %2: list of keynames */
		return tr("Delete the %1 keys: %2?");
	}
	return pki_base::getMsg(msg);
}

QString pki_key::getIntNameWithType()
{
	return QString("%1 (%2:%3%4)").arg(getIntName()).arg(getTypeString()).
		arg(length()).arg(isPubKey() ?
			QString(" ") + tr("public key") : QString(""));
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
#ifndef OPENSSL_NO_EC
int pki_key::ecParamNid()
{
	if (key->type != EVP_PKEY_EC)
		return NID_undef;
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
#endif

QList<int> pki_key::possibleHashNids()
{
	QList<int> nids;

	switch (EVP_PKEY_type(key->type)) {
		case EVP_PKEY_RSA:
			nids << NID_md5 << NID_sha1 << NID_sha224 << NID_sha256 <<
				NID_sha384 << NID_sha512 << NID_ripemd160;
			break;
		case EVP_PKEY_DSA:
			nids << NID_sha1;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
			nids << NID_sha256;
#endif
			break;
		case EVP_PKEY_EC:
			nids << NID_sha1;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
			nids << NID_sha224 << NID_sha256 << NID_sha384 << NID_sha512;
#endif
			break;
	}
	return nids;
};

bool pki_key::compare(pki_base *ref)
{
	pki_key *kref = (pki_key *)ref;

	if (kref->getKeyType() != getKeyType())
		return false;
	if (!kref || !kref->key || !key)
		return false;

	int r = EVP_PKEY_cmp(key, kref->key);
	pki_openssl_error();
	return r == 1;
}

void pki_key::writePublic(const QString fname, bool pem)
{
	FILE *fp = fopen_write(fname);
	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	if (pem)
		PEM_write_PUBKEY(fp, key);
	else
		i2d_PUBKEY_fp(fp, key);

	fclose(fp);
	pki_openssl_error();
}

QString pki_key::BNoneLine(BIGNUM *bn) const
{
	QString x;
	if (bn) {
		char *hex = BN_bn2hex(bn);
		x = hex;
		OPENSSL_free(hex);
		pki_openssl_error();
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
	pki_openssl_error();
	return x;
}

QVariant pki_key::column_data(dbheader *hd)
{
	QStringList sl;
	sl << tr("Common") << tr("Private") << tr("Bogus") << tr("PIN");
	switch (hd->id) {
		case HD_key_type:
			return QVariant(getTypeString());
		case HD_key_size:
			return QVariant(length());
		case HD_key_use:
			return QVariant(getUcount());
		case HD_key_passwd:
			if (isPubKey())
				return QVariant(tr("No password"));
			if (ownPass<0 || ownPass>3)
				return QVariant("Holla die Waldfee");
			return QVariant(sl[ownPass]);
		case HD_key_curve:
			QString r;
#ifndef OPENSSL_NO_EC
			if (key->type == EVP_PKEY_EC)
				r = OBJ_nid2sn(ecParamNid());
#endif
			return QVariant(r);
	}
	return pki_base::column_data(hd);
}

BIGNUM *pki_key::ssh_key_data2bn(QByteArray *ba, bool skip)
{
	const unsigned char *d = (const unsigned char *)ba->constData();
	uint32_t len;
	BIGNUM *bn = NULL;

	if (ba->size() < 4)
			throw errorEx(tr("Invalid SSH2 public key"));
	len = (d[0] << 24) + (d[1] << 16) + (d[2] << 8) + d[3];
	if (!skip) {
		bn = BN_bin2bn(d+4, len, NULL);
		if (!ba)
			throw errorEx(tr("Invalid SSH2 public key"));
	}
	if (ba->size() < (ssize_t)len + 4)
		throw errorEx(tr("Invalid SSH2 public key"));
	ba->remove(0, len+4);
	return bn;
}

EVP_PKEY *pki_key::load_ssh2_key(FILE *fp)
{
	/* See RFC 4253 Section 6.6 */
	QByteArray ba;
	QStringList sl;
	int type;
	EVP_PKEY *pk = NULL;

	ba.resize(4096);

	if (!fgets(ba.data(), ba.size(), fp)) {
		return NULL;
	}
	sl = QString(ba).split(" ", QString::SkipEmptyParts);
	if (sl.size() < 2)
		return NULL;
	if (sl[0].startsWith("ssh-rsa"))
		type = EVP_PKEY_RSA;
	else if (sl[0].startsWith("ssh-dss"))
		type = EVP_PKEY_DSA;
	else
		return NULL;

	ba = QByteArray::fromBase64(sl[1].toLatin1());
	switch (type) {
		case EVP_PKEY_RSA: {
			RSA *rsa = RSA_new();
			/* Skip "ssh-rsa..." */
			ssh_key_data2bn(&ba, true);
			rsa->e = ssh_key_data2bn(&ba);
			rsa->n = ssh_key_data2bn(&ba);
			pk = EVP_PKEY_new();
			EVP_PKEY_assign_RSA(pk, rsa);
			break;
		}
		case EVP_PKEY_DSA: {
			DSA *dsa = DSA_new();
			/* Skip "ssh-dsa..." */
			ssh_key_data2bn(&ba, true);
			dsa->p = ssh_key_data2bn(&ba);
			dsa->q = ssh_key_data2bn(&ba);
			dsa->g = ssh_key_data2bn(&ba);
			dsa->pub_key = ssh_key_data2bn(&ba);
			pk = EVP_PKEY_new();
			EVP_PKEY_assign_DSA(pk, dsa);
		}
	}
	return pk;
}

void pki_key::ssh_key_QBA2data(QByteArray &ba, QByteArray *data)
{
	int size = ba.size();
	unsigned char p[4];

	p[0] = (size >> 24) & 0xff;
	p[1] = (size >> 16) & 0xff;
	p[2] = (size >>  8) & 0xff;
	p[3] = size & 0xff;
	data->append((char*)p, sizeof p);
	data->append(ba);
}

void pki_key::ssh_key_bn2data(BIGNUM *bn, QByteArray *data)
{
	QByteArray big;
	big.resize(BN_num_bytes(bn));
	BN_bn2bin(bn, (unsigned char *)big.data());
	pki_openssl_error();
	if ((unsigned char)big[0] >= 0x80)
		big.prepend('\0');
	ssh_key_QBA2data(big, data);
}

QByteArray pki_key::SSH2publicQByteArray()
{
	QByteArray txt, data;

	switch (key->type) {
	case EVP_PKEY_RSA:
		txt = "ssh-rsa";
		ssh_key_QBA2data(txt, &data);
		ssh_key_bn2data(key->pkey.rsa->e, &data);
		ssh_key_bn2data(key->pkey.rsa->n, &data);
		break;
	case EVP_PKEY_DSA:
		txt = "ssh-dss";
		ssh_key_QBA2data(txt, &data);
		ssh_key_bn2data(key->pkey.dsa->p, &data);
		ssh_key_bn2data(key->pkey.dsa->q, &data);
		ssh_key_bn2data(key->pkey.dsa->g, &data);
		ssh_key_bn2data(key->pkey.dsa->pub_key, &data);
		break;
	default:
		return QByteArray();
	}
	return txt + " " + data.toBase64() + "\n";
}

void pki_key::writeSSH2public(QString fname)
{
	QFile f(fname);

	if (!f.open(QIODevice::ReadWrite))
		fopen_error(fname);
	else {
		QByteArray txt = SSH2publicQByteArray();
		if (f.write(txt) != txt.size())
			throw errorEx(tr("Failed writing to %1").arg(fname));
		f.close();
	}
}
