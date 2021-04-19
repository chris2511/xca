/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_key.h"
#include "pki_x509super.h"
#include "func.h"
#include "db.h"
#include "pkcs11.h"
#include "widgets/XcaWarning.h"
#include "widgets/ExportDialog.h"

#include <openssl/rand.h>
#include <openssl/pem.h>

#include "openssl_compat.h"

builtin_curves builtinCurves;

pki_key::pki_key(const QString &name)
        :pki_base(name)
{
	key = EVP_PKEY_new();
	key_size = 0;
	isPub = true;
	useCount = -1;
}

pki_key::pki_key(const pki_key *pk)
	:pki_base(pk)
{
	if (pk->key) {
		QByteArray ba = i2d_bytearray(I2D_VOID(i2d_PUBKEY), pk->key);
		key = NULL;
		d2i(ba);
		sqlItemId = pk->sqlItemId;
	} else {
		key = EVP_PKEY_new();
	}
	key_size = pk->key_size;
	useCount = -1;
}

pki_key::~pki_key()
{
	if (key)
		EVP_PKEY_free(key);
}

void pki_key::autoIntName(const QString &file)
{
	pki_base::autoIntName(file);
	if (!getIntName().isEmpty())
		return;
	setIntName(QString("%1 %2%3").arg(length(), getTypeString(),
		isPubKey() ? QString(" ") + tr("Public key") : QString()));
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

QByteArray pki_key::i2d() const
{
        return i2d_bytearray(I2D_VOID(i2d_PUBKEY), key);
}

void pki_key::write_SSH2_ed25519_private(BIO *b,
			 const EVP_PKEY *pkey, const EVP_CIPHER *enc) const
{
#ifndef OPENSSL_NO_EC
	static const char data0001[] = { 0, 0, 0, 1};
	char buf_nonce[8];
	QByteArray data, priv, pubfull;
	(void)enc;

	pubfull = SSH2publicQByteArray(true);
	RAND_bytes((unsigned char*)buf_nonce, sizeof buf_nonce);
	priv.append(buf_nonce, sizeof buf_nonce);
	priv += pubfull;
	ssh_key_QBA2data(ed25519PrivKey(pkey) + ed25519PubKey(), &priv);

	data = "openssh-key-v1";
	data.append('\0');
	ssh_key_QBA2data("none", &data); // enc-alg
	ssh_key_QBA2data("none", &data); // KDF name
	ssh_key_QBA2data("", &data); // KDF data
	data.append(data0001, sizeof data0001);
	ssh_key_QBA2data(pubfull, &data);
	ssh_key_QBA2data(priv, &data);

	PEM_write_bio(b, PEM_STRING_OPENSSH_KEY, (char*)"",
		(unsigned char*)(data.data()), data.size());
	pki_openssl_error();
#endif
}

bool pki_key::pem(BioByteArray &b, int format)
{
	EVP_PKEY *pkey;
	QByteArray ba;
	int keytype;

	switch (format) {
	case exportType::SSH2_public:
		b += SSH2publicQByteArray();
		break;
	case exportType::PEM_private:
	case exportType::SSH2_private:
		pkey = decryptKey();
		keytype = EVP_PKEY_id(pkey);
		switch (keytype) {
		case EVP_PKEY_RSA:
			PEM_write_bio_RSAPrivateKey(b,
				EVP_PKEY_get0_RSA(pkey),
				NULL, NULL, 0, NULL, NULL);
			break;
		case EVP_PKEY_DSA:
			PEM_write_bio_DSAPrivateKey(b,
				EVP_PKEY_get0_DSA(pkey),
				NULL, NULL, 0, NULL, NULL);
			break;
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
			PEM_write_bio_ECPrivateKey(b,
				EVP_PKEY_get0_EC_KEY(pkey),
				NULL, NULL, 0, NULL, NULL);
			break;
#ifdef EVP_PKEY_ED25519
		case EVP_PKEY_ED25519:
			if (format == exportType::PEM_private)
				return false;
			write_SSH2_ed25519_private(b, pkey, NULL);
			break;
#endif
#endif
		}
		EVP_PKEY_free(pkey);
		break;
	case exportType::PKCS8:
		pkey = decryptKey();
		PEM_write_bio_PrivateKey(b, pkey, NULL, NULL, 0, NULL, NULL);
		EVP_PKEY_free(pkey);
		break;
	case exportType::PEM_key:
		PEM_write_bio_PUBKEY(b, key);
		break;
	default:
		return false;
	}
	return true;
}

void pki_key::writeSSH2private(XFile &file, pem_password_cb *cb) const
{
	(void)cb;
//	pass_info p(XCA_TITLE, tr("Please enter the password protecting the SSH2 private key '%1'").arg(getIntName()));

	EVP_PKEY *pkey = decryptKey();
	if (!pkey) {
		pki_openssl_error();
		return;
	}
	write_SSH2_ed25519_private(file.bio(), pkey, NULL);
}

QString pki_key::length() const
{
	bool dsa_unset = false;

	if (EVP_PKEY_id(key) == EVP_PKEY_DSA) {
		const BIGNUM *p = NULL;
		DSA *dsa = EVP_PKEY_get0_DSA(key);
		if (dsa)
			DSA_get0_pqg(dsa, &p, NULL, NULL);
		dsa_unset = p == NULL;
	}

	if (dsa_unset)
		return QString("???");

	return QString("%1 bit").arg(EVP_PKEY_bits(key));
}

/* getKeyTypeString() returns RSA
 * getTypeString() returns RSA or "Token RSA" for tokens
 */
QString pki_key::getKeyTypeString() const
{
	return keytype::byPKEY(key).name;
}

QString pki_key::getTypeString() const
{
	return getKeyTypeString();
}

QString pki_key::getMsg(msg_type msg) const
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

QString pki_key::comboText() const
{
	return QString("%1 (%2:%3%4)").arg(getIntName()).arg(getTypeString()).
		arg(length()).arg(isPubKey() ?
			QString(" ") + tr("Public key") : QString(""));
}

bool pki_key::isToken()
{
	return false;
}

bool pki_key::isPrivKey() const
{
	return !isPubKey();
}

int pki_key::getUcount() const
{
	XSqlQuery q;
	if (useCount != -1)
		return useCount;
	int size = -1;
	SQL_PREPARE(q, "SELECT COUNT(*) FROM x509super WHERE pkey=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	if (q.first())
		size = q.value(0).toInt();
	else
		qDebug("Failed to get key count for %s", CCHAR(getIntName()));
	XCA_SQLERROR(q.lastError());
	useCount = size;
	return size;
}

int pki_key::getKeyType() const
{
	return EVP_PKEY_id(key);
}

QString pki_key::modulus() const
{
	if (getKeyType() == EVP_PKEY_RSA) {
		const BIGNUM *n = NULL;

		RSA *rsa = EVP_PKEY_get0_RSA(key);
		RSA_get0_key(rsa, &n, NULL, NULL);
		return BN2QString(n);
	}
	return QString();
}

QString pki_key::pubEx() const
{
	if (getKeyType() == EVP_PKEY_RSA) {
		const BIGNUM *e = NULL;
		RSA *rsa = EVP_PKEY_get0_RSA(key);
		RSA_get0_key(rsa, NULL, &e, NULL);
		return BN2QString(e);
	}
	return QString();
}

QString pki_key::subprime() const
{
	if (getKeyType() == EVP_PKEY_DSA) {
		const BIGNUM *q = NULL;
		DSA *dsa = EVP_PKEY_get0_DSA(key);
		if (dsa)
			DSA_get0_pqg(dsa, NULL, &q, NULL);
		return BN2QString(q);
	}
	return QString();
}

QString pki_key::pubkey() const
{
	if (getKeyType() == EVP_PKEY_DSA) {
		const BIGNUM *pubkey = NULL;
		DSA *dsa = EVP_PKEY_get0_DSA(key);
		if (dsa)
			DSA_get0_key(dsa, &pubkey, NULL);
		return BN2QString(pubkey);
	}
	return QString();
}
#ifndef OPENSSL_NO_EC
int pki_key::ecParamNid() const
{
	const EC_KEY *ec;

	if (getKeyType() != EVP_PKEY_EC)
		return NID_undef;
	ec = EVP_PKEY_get0_EC_KEY(key);
	return EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
}

BIGNUM *pki_key::ecPubKeyBN() const
{
	if (getKeyType() != EVP_PKEY_EC)
		return NULL;

	const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(key);
	return EC_POINT_point2bn(EC_KEY_get0_group(ec),
				 EC_KEY_get0_public_key(ec),
				 EC_KEY_get_conv_form(ec), NULL, NULL);
}

QString pki_key::ecPubKey() const
{
	QString pub;
	BIGNUM *pub_key = ecPubKeyBN();
	if (pub_key) {
		pub = BN2QString(pub_key);
		BN_free(pub_key);
	}
	return pub;
}

#ifdef EVP_PKEY_ED25519
static QByteArray ed25519Key(int(*EVP_PKEY_get_raw)
			(const EVP_PKEY*, unsigned char *, size_t *),
			const EVP_PKEY *pkey)
{
	unsigned char k[ED25519_KEYLEN];
	size_t len = sizeof k;

	if (EVP_PKEY_id(pkey) == EVP_PKEY_ED25519 &&
	    EVP_PKEY_get_raw(pkey, k, &len))
		return QByteArray((char*)k, len);
	return QByteArray();
}

QByteArray pki_key::ed25519PubKey() const
{
	return ed25519Key(EVP_PKEY_get_raw_public_key, key);
}

QByteArray pki_key::ed25519PrivKey(const EVP_PKEY *pkey) const
{
	return ed25519Key(EVP_PKEY_get_raw_private_key, pkey);
}
#else

QByteArray pki_key::ed25519PubKey() const
{
	return QByteArray();
}

QByteArray pki_key::ed25519PrivKey(const EVP_PKEY *) const
{
	return QByteArray();
}

#endif
#endif

QList<int> pki_key::possibleHashNids()
{
	QList<int> nids;

	switch (EVP_PKEY_type(getKeyType())) {
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

bool pki_key::compare(const pki_base *ref) const
{
	const pki_key *kref = (pki_key *)ref;

	if (kref->getKeyType() != getKeyType())
		return false;
	if (!kref || !kref->key || !key)
		return false;

	int r = EVP_PKEY_cmp(key, kref->key);
	pki_openssl_error();
	return r == 1;
}

void pki_key::writePublic(XFile &file, bool pem) const
{
	if (pem) {
		PEM_file_comment(file);
		PEM_write_PUBKEY(file.fp(), key);
	} else {
		i2d_PUBKEY_fp(file.fp(), key);
	}
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

QString pki_key::BN2QString(const BIGNUM *bn) const
{
	if (bn == NULL)
		return "--";
	QString x="";
	char zs[10];
	int j, size = BN_num_bytes(bn);
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

QVariant pki_key::column_data(const dbheader *hd) const
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
			if (getKeyType() == EVP_PKEY_EC)
				r = OBJ_nid2sn(ecParamNid());
#endif
			return QVariant(r);
	}
	return pki_base::column_data(hd);
}

QSqlError pki_key::insertSqlData()
{
	unsigned myhash = hash();
	XSqlQuery q;
	QList<pki_x509super*> list;

	SQL_PREPARE(q, "SELECT item FROM x509super WHERE key_hash=? AND "
			"pkey IS NULL");
	q.bindValue(0, myhash);
	q.exec();
	if (q.lastError().isValid())
		return q.lastError();

	while (q.next()) {
		pki_x509super *x;
		x = Store.lookupPki<pki_x509super>(q.value(0));
		if (!x) {
			qDebug("X509 Super class with id %d not found",
				q.value(0).toInt());
			continue;
		}
		if (x->compareRefKey(this)) {
			x->setRefKey(this);
			list << x;
		}
	}
	q.finish();

	SQL_PREPARE(q, "UPDATE x509super SET pkey=? WHERE item=?");
	q.bindValue(0, sqlItemId);
	foreach(pki_x509super* x, list) {
		q.bindValue(1, x->getSqlItemId());
		q.exec();
		AffectedItems(x->getSqlItemId());
		if (q.lastError().isValid())
			return q.lastError();
	}
	q.finish();

	SQL_PREPARE(q, "INSERT INTO public_keys (item, type, hash, len, \"public\") "
		  "VALUES (?, ?, ?, ?, ?)");
	q.bindValue(0, sqlItemId);
	q.bindValue(1, getKeyTypeString().left(4));
	q.bindValue(2, myhash);
	q.bindValue(3, EVP_PKEY_bits(key));
	q.bindValue(4, i2d_b64());
	q.exec();
	return q.lastError();
}

void pki_key::restoreSql(const QSqlRecord &rec)
{
	pki_base::restoreSql(rec);
	QByteArray ba = QByteArray::fromBase64(
			rec.value(VIEW_public_keys_public).toByteArray());
	d2i(ba);
	key_size = rec.value(VIEW_public_keys_len).toInt();
}

QSqlError pki_key::deleteSqlData()
{
	XSqlQuery q;
	QSqlError e;

	SQL_PREPARE(q, "DELETE FROM public_keys WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	e = q.lastError();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "UPDATE x509super SET pkey=NULL WHERE pkey=?");
	q.bindValue(0, sqlItemId);
	AffectedItems(sqlItemId);
	q.exec();
	return q.lastError();
}

void pki_key::ssh_key_check_chunk(QByteArray *ba, const char *expect) const
{
	QByteArray chunk = ssh_key_next_chunk(ba);

	if (chunk != expect)
		throw errorEx(tr("Unexpected SSH2 content: '%1'")
				.arg(QString(chunk)));
}

BIGNUM *pki_key::ssh_key_data2bn(QByteArray *ba) const
{
	QByteArray chunk = ssh_key_next_chunk(ba);
	BIGNUM *bn = BN_bin2bn((const unsigned char *)chunk.constData(),
				chunk.size(), NULL);
	check_oom(bn);
	return bn;
}

QByteArray pki_key::ssh_key_next_chunk(QByteArray *ba) const
{
	QByteArray chunk;
	const char *d;
	int len;

	if (!ba || ba->size() < 4)
		throw errorEx(tr("Invalid SSH2 public key"));

	d = ba->constData();
	len = (d[0] << 24) + (d[1] << 16) + (d[2] << 8) + d[3];

	if (ba->size() < len + 4)
		throw errorEx(tr("Invalid SSH2 public key"));
	chunk = ba->mid(4, len);
	ba->remove(0, len +4);
	return chunk;
}

EVP_PKEY *pki_key::load_ssh2_key(XFile &file)
{
	/* See RFC 4253 Section 6.6 */
	QByteArray ba;
	QStringList sl;
	EVP_PKEY *pk = NULL;

	ba = file.read(4096);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
	sl = QString(ba).split(" ", Qt::SkipEmptyParts);
#else
	sl = QString(ba).split(" ", QString::SkipEmptyParts);
#endif
	if (sl.size() < 2)
		return NULL;

	ba = QByteArray::fromBase64(sl[1].toLatin1());
	if (sl[0].startsWith("ssh-rsa")) {
		ssh_key_check_chunk(&ba, "ssh-rsa");

		BIGNUM *e = ssh_key_data2bn(&ba);
		BIGNUM *n = ssh_key_data2bn(&ba);

		RSA *rsa = RSA_new();
		check_oom(rsa);
		RSA_set0_key(rsa, n, e, NULL);
		pk = EVP_PKEY_new();
		check_oom(pk);
		EVP_PKEY_assign_RSA(pk, rsa);
	} else if (sl[0].startsWith("ssh-dss")) {
		ssh_key_check_chunk(&ba, "ssh-dss");
		BIGNUM *p = ssh_key_data2bn(&ba);
		BIGNUM *q = ssh_key_data2bn(&ba);
		BIGNUM *g = ssh_key_data2bn(&ba);
		BIGNUM *pubkey = ssh_key_data2bn(&ba);
		DSA *dsa = DSA_new();
		check_oom(dsa);

		DSA_set0_pqg(dsa, p, q, g);
		DSA_set0_key(dsa, pubkey, NULL);

		pk = EVP_PKEY_new();
		check_oom(pk);
		EVP_PKEY_assign_DSA(pk, dsa);
#ifndef OPENSSL_NO_EC
	} else if (sl[0].startsWith("ecdsa-sha2-nistp256")) {
		EC_KEY *ec;

		/* Skip "ecdsa-sha2..." */
		ssh_key_check_chunk(&ba, "ecdsa-sha2-nistp256");
		ssh_key_check_chunk(&ba, "nistp256");
		BIGNUM *bn = ssh_key_data2bn(&ba);

		ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		check_oom(ec);
		EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
		EC_KEY_set_public_key(ec, EC_POINT_bn2point(
					EC_KEY_get0_group(ec), bn, NULL, NULL));
		BN_free(bn);
		pki_openssl_error();

		pk = EVP_PKEY_new();
		check_oom(pk);
		EVP_PKEY_assign_EC_KEY(pk, ec);
#ifdef EVP_PKEY_ED25519
	} else if (sl[0].startsWith("ssh-ed25519")) {
		ssh_key_check_chunk(&ba, "ssh-ed25519");
		QByteArray pub = ssh_key_next_chunk(&ba);
		pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
			(const unsigned char *)pub.constData(), pub.count());
		pki_openssl_error();
#endif
#endif
	} else {
		throw errorEx(tr("Unexpected SSH2 content: '%1'").arg(sl[0]));
	}
	if (sl.size() > 2 && pk)
		setComment(sl[2].section('\n', 0, 0));

	return pk;
}

void pki_key::ssh_key_QBA2data(const QByteArray &ba, QByteArray *data) const
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

void pki_key::ssh_key_bn2data(const BIGNUM *bn, QByteArray *data) const
{
	QByteArray big;
	big.resize(BN_num_bytes(bn));
	BN_bn2bin(bn, (unsigned char *)big.data());
	pki_openssl_error();
	if ((unsigned char)big[0] >= 0x80)
		big.prepend('\0');
	ssh_key_QBA2data(big, data);
}

bool pki_key::SSH2_compatible() const
{
	switch (getKeyType()) {
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		return ecParamNid() == NID_X9_62_prime256v1;
#ifdef EVP_PKEY_ED25519
	case EVP_PKEY_ED25519:
#endif
#endif
	case EVP_PKEY_RSA:
	case EVP_PKEY_DSA:
		return true;
	}
	return false;
}

QByteArray pki_key::SSH2publicQByteArray(bool raw) const
{
	QByteArray txt, data;
	switch (getKeyType()) {
	case EVP_PKEY_RSA:
		txt = "ssh-rsa";
		ssh_key_QBA2data(txt, &data);
		{
			RSA *rsa = EVP_PKEY_get0_RSA(key);
			const BIGNUM *n, *e;
			RSA_get0_key(rsa, &n, &e, NULL);
			ssh_key_bn2data(e, &data);
			ssh_key_bn2data(n, &data);
		}
		break;
	case EVP_PKEY_DSA:
		txt = "ssh-dss";
		ssh_key_QBA2data(txt, &data);
		{
			DSA *dsa = EVP_PKEY_get0_DSA(key);
			const BIGNUM *p, *q, *g, *pubkey;
			DSA_get0_pqg(dsa, &p, &q, &g);
			DSA_get0_key(dsa, &pubkey, NULL);
			ssh_key_bn2data(p, &data);
			ssh_key_bn2data(q, &data);
			ssh_key_bn2data(g, &data);
			ssh_key_bn2data(pubkey, &data);
		}
		break;
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		if (ecParamNid() != NID_X9_62_prime256v1)
			return QByteArray();

		txt = "ecdsa-sha2-nistp256";
		ssh_key_QBA2data(txt, &data);
		ssh_key_QBA2data("nistp256", &data);
		{
			BIGNUM *bn = ecPubKeyBN();
			ssh_key_bn2data(bn, &data);
			BN_free(bn);
		}
		pki_openssl_error();
		break;
#ifdef EVP_PKEY_ED25519
	case EVP_PKEY_ED25519:
		txt = "ssh-ed25519";
		ssh_key_QBA2data(txt, &data);
		ssh_key_QBA2data(ed25519PubKey(), &data);
		break;
#endif
#endif
	default:
		return QByteArray();
	}
	if (raw)
		return data;

	txt += " " + data.toBase64();
	QString comm = comment.section('\n', 0, 0).simplified();
	if (comm.size() > 0)
		txt += " " + comm.toUtf8();
	return txt + "\n";
}

void pki_key::writeSSH2public(XFile &file) const
{
	QByteArray txt = SSH2publicQByteArray();
	if (file.write(txt) != txt.size())
		throw errorEx(tr("Failed writing to %1").arg(file.fileName()));
}

bool pki_key::verify(EVP_PKEY *pkey) const
{
	bool verify = true;
	const BIGNUM *a = NULL;
	const BIGNUM *b = NULL;
	const BIGNUM *c = NULL;

	switch (EVP_PKEY_type(EVP_PKEY_id(pkey))) {
	case EVP_PKEY_RSA:
		RSA_get0_key(EVP_PKEY_get0_RSA(pkey), &a, &b, NULL);
		verify = a && b;
		break;
	case EVP_PKEY_DSA:
		DSA_get0_pqg(EVP_PKEY_get0_DSA(pkey), &a, &b, &c);
		verify = a && b && c;
		break;
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		verify = EC_KEY_check_key(EVP_PKEY_get0_EC_KEY(pkey)) == 1;
		break;
#ifdef EVP_PKEY_ED25519
	case EVP_PKEY_ED25519: {
		size_t len;
		verify = EVP_PKEY_get_raw_private_key(pkey, NULL, &len) == 1 &&
				len == ED25519_KEYLEN;
		break;
	}
#endif
#endif
	default:
		verify = false;
	}
	if (verify)
		verify = verify_priv(pkey);
	pki_openssl_error();
	return verify;
}

bool pki_key::verify_priv(EVP_PKEY *) const
{
	return true;
}

QString pki_key::fingerprint(const QString &format) const
{
	const EVP_MD *md;
	QByteArray data;
	QStringList sl = format.toLower().split(" ");

	if (sl.size() < 2)
		return QString("Invalid format: %1").arg(format);
	if (sl[0] == "ssh")
		data = SSH2publicQByteArray(true);
	else if (sl[0] == "x509")
		data = X509_PUBKEY_public_key();
	else if (sl[0] == "der")
		data = i2d_bytearray(I2D_VOID(i2d_PUBKEY), key);
	else
		return QString("Invalid format: %1").arg(sl[0]);

	md = EVP_get_digestbyname(CCHAR(sl[1]));
	if (!md)
		return QString("Invalid hash: %1").arg(sl[1]);

	if (sl.size() > 2 && sl[2] == "b64") {
		QString s(Digest(data, md).toBase64());
		s.chop(1);
		return s;
	}
	return ::fingerprint(data, md);
}

QByteArray pki_key::X509_PUBKEY_public_key() const
{
	X509_PUBKEY *pk = NULL;
	const unsigned char *p;
	int len;

	X509_PUBKEY_set(&pk, key);
#if OPENSSL_VERSION_NUMBER < 0x10000000L
	p = pk->public_key->data;
	len = pk->public_key->length;
#else
	X509_PUBKEY_get0_param(NULL, &p, &len, NULL, pk);
#endif

	QByteArray data((const char*)p, len);
	X509_PUBKEY_free(pk);
	return data;
}

void pki_key::PEM_file_comment(XFile &file) const
{
	if (!pem_comment)
		return;
	pki_base::PEM_file_comment(file);
	file.write(QString("%1 %2\n").arg(length(), getTypeString())
			.toUtf8());
}

void pki_key::collect_properties(QMap<QString, QString> &prp) const
{
	QStringList sl;
	sl << getTypeString() << length();
	if (isPubKey())
		sl << tr("Public key");
#ifndef OPENSSL_NO_EC
	if (getKeyType() == EVP_PKEY_EC)
		sl << QString(OBJ_nid2ln(ecParamNid()));
#endif
	prp["Key"] = sl.join(" ");
	pki_base::collect_properties(prp);
}

void pki_key::print(BioByteArray &bba, enum print_opt opt) const
{
	pki_base::print(bba, opt);
	switch (opt) {
	case print_openssl_txt:
#if OPENSSL_VERSION_NUMBER < 0x10000000L
		bba += "Not supported\n";
#else
		EVP_PKEY_print_public(bba, key, 0, NULL);
#endif
		break;
	case print_pem:
		PEM_write_bio_PUBKEY(bba, key);
		break;
	case print_coloured:
		break;
	}
}
