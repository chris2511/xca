/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_evp.h"
#include "pass_info.h"
#include "func.h"
#include "db.h"
#include "entropy.h"
#include "widgets/PwDialog.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include <QProgressDialog>
#include <QApplication>
#include <QDir>

#include "openssl_compat.h"

Passwd pki_evp::passwd;
Passwd pki_evp::oldpasswd;

QString pki_evp::passHash = QString();

QPixmap *pki_evp::icon[2]= { NULL, NULL };

void pki_evp::init()
{
	ownPass = ptCommon;
	pkiType = asym_key;
}

void pki_evp::setOwnPass(enum passType x)
{
	EVP_PKEY *pk=NULL, *pk_back = key;
	enum passType oldOwnPass = ownPass;

	if (ownPass == x || isPubKey())
		return;

	try {
		pk = decryptKey();
		if (pk == NULL)
			return;

		key = pk;
		ownPass = x;
		encryptKey();
	}
	catch (errorEx &err) {
		if (pk)
			EVP_PKEY_free(pk);
		key = pk_back;
		ownPass = oldOwnPass;
		throw(err);
	}
}

bool pki_evp::sqlUpdatePrivateKey()
{
	Transaction;
	if (!TransBegin())
		return false;
	XSqlQuery q;
	SQL_PREPARE(q, "UPDATE private_keys SET private=?, ownPass=? "
		"WHERE item=?");
	q.bindValue(0, encKey_b64());
	q.bindValue(1, ownPass);
	q.bindValue(2, sqlItemId);
	AffectedItems(sqlItemId);
	q.exec();

	encKey.fill(0);
	encKey.clear();

	if (!q.lastError().isValid() && q.numRowsAffected() == 1) {
		TransCommit();
		return true;
	}
	return false;
}

void pki_evp::generate(int bits, int type, QProgressBar *progress, int curve_nid)
{
	Entropy::seed_rng();

#ifdef OPENSSL_NO_EC
	(void)curve_nid;
#endif
	progress->setMinimum(0);
	progress->setMaximum(100);
	progress->setValue(50);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	BN_GENCB _bar, *bar = &_bar;
#else
	BN_GENCB *bar = BN_GENCB_new();
#endif
	BN_GENCB_set_old(bar, inc_progress_bar, progress);

	switch (type) {
	case EVP_PKEY_RSA: {
		RSA *rsakey = RSA_new();
		BIGNUM *e = BN_new();
		BN_set_word(e, 0x10001);
		if (RSA_generate_key_ex(rsakey, bits, e, bar))
			EVP_PKEY_assign_RSA(key, rsakey);
		else
			RSA_free(rsakey);
		BN_free(e);
		break;
	}
	case EVP_PKEY_DSA: {
		DSA *dsakey = DSA_new();
		progress->setMaximum(500);
		if (DSA_generate_parameters_ex(dsakey, bits, NULL, 0, NULL,
		    NULL, bar) && DSA_generate_key(dsakey))
				EVP_PKEY_assign_DSA(key, dsakey);
		else
			DSA_free(dsakey);
		break;
	}
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		EC_KEY *eckey;
		EC_GROUP *group = EC_GROUP_new_by_curve_name(curve_nid);
		if (!group)
			break;
		eckey = EC_KEY_new();
		if (eckey == NULL) {
			EC_GROUP_free(group);
			break;
		}
		EC_GROUP_set_asn1_flag(group, 1);
		if (EC_KEY_set_group(eckey, group)) {
			if (EC_KEY_generate_key(eckey)) {
				EVP_PKEY_assign_EC_KEY(key, eckey);
				EC_GROUP_free(group);
				break;
			}
		}
		EC_KEY_free(eckey);
		EC_GROUP_free(group);
		break;
#endif
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	BN_GENCB_free(bar);
#endif
	isPub = false;
	pkiSource = generated;
	pki_openssl_error();
	encryptKey();
}

pki_evp::pki_evp(const pki_evp *pk)
	:pki_key(pk)
{
	init();
	pki_openssl_error();
	ownPass = pk->ownPass;
	isPub = pk->isPub;
	encKey = pk->getEncKey();
}

pki_evp::pki_evp(const QString name, int type)
	:pki_key(name)
{
	init();
	EVP_PKEY_set_type(key, type);
	pki_openssl_error();
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static bool EVP_PKEY_isPrivKey(EVP_PKEY *key)
{
	const BIGNUM *b;
	int keytype = EVP_PKEY_id(key);

	switch (EVP_PKEY_type(keytype)) {
		case EVP_PKEY_RSA:
			RSA_get0_key(EVP_PKEY_get0_RSA(key), NULL, NULL, &b);
			return b ? true: false;
		case EVP_PKEY_DSA:
			DSA_get0_key(EVP_PKEY_get0_DSA(key), NULL, &b);
			return b ? true: false;
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
			return EC_KEY_get0_private_key(
				EVP_PKEY_get0_EC_KEY(key)) ? true: false;
#endif
	}
	return false;
}

#else

static bool EVP_PKEY_isPrivKey(EVP_PKEY *key)
{
	int keytype;

	keytype = EVP_PKEY_id(key);

	switch (EVP_PKEY_type(keytype)) {
		case EVP_PKEY_RSA:
			return key->pkey.rsa->d ? true: false;
		case EVP_PKEY_DSA:
			return key->pkey.dsa->priv_key ? true: false;
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
			return EC_KEY_get0_private_key(key->pkey.ec) ? true: false;
#endif
	}
	return false;
}
#endif

pki_evp::pki_evp(EVP_PKEY *pkey)
	:pki_key()
{
	init();
	set_EVP_PKEY(pkey);
}

void pki_evp::openssl_pw_error(QString fname)
{
	switch (ERR_peek_error() & 0xff000fff) {
	case ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_DECRYPT):
	case ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_PASSWORD_READ):
	case ERR_PACK(ERR_LIB_EVP, 0, EVP_R_BAD_DECRYPT):
		pki_ign_openssl_error();
		throw errorEx(tr("Failed to decrypt the key (bad password) ")+
				fname, getClassName(), E_PASSWD);
	}
}

void pki_evp::set_EVP_PKEY(EVP_PKEY *pkey)
{
	if (!pkey)
		return;
	if (key)
		EVP_PKEY_free(key);
	key = pkey;
	isPub = !EVP_PKEY_isPrivKey(key);
	if (!isPub) {
		bogusEncryptKey();
	}
	pki_openssl_error();
}

void pki_evp::fromPEMbyteArray(QByteArray &ba, QString name)
{
	BIO *bio = BIO_new_mem_buf(ba.data(), ba.length());
	EVP_PKEY *pkey;
	pass_info p(XCA_TITLE,
		tr("Please enter the password to decrypt the private key.") +
		" " + name);
	pkey = PEM_read_bio_PrivateKey(bio, NULL, PwDialog::pwCallback, &p);
	openssl_pw_error(name);
	if (!pkey){
		pki_ign_openssl_error();
		BIO_free(bio);
		bio = BIO_new_mem_buf(ba.data(), ba.length());
		pkey = PEM_read_bio_PUBKEY(bio, NULL, PwDialog::pwCallback, &p);
	}
	BIO_free(bio);

	setIntName(rmslashdot(name));
	set_EVP_PKEY(pkey);
	autoIntName();
	if (getIntName().isEmpty())
		setIntName(rmslashdot(name));
}

static void search_ec_oid(EVP_PKEY *pkey)
{
#ifndef OPENSSL_NO_EC
	EC_KEY *ec;
	int keytype = EVP_PKEY_id(pkey);

	if (keytype != EVP_PKEY_EC)
		return;

	ec = EVP_PKEY_get0_EC_KEY(pkey);

	const EC_GROUP *ec_group = EC_KEY_get0_group(ec);
	EC_GROUP *builtin;

	if (!ec_group)
		return;
	if (EC_GROUP_get_curve_name(ec_group))
		return;
	/* There is an EC_GROUP with a missing OID
	 * because of explicit parameters */
	foreach(builtin_curve curve, pki_key::builtinCurves) {
		builtin = EC_GROUP_new_by_curve_name(curve.nid);
		if (EC_GROUP_cmp(builtin, ec_group, NULL) == 0) {
			EC_GROUP_set_curve_name((EC_GROUP *)ec_group, curve.nid);
			EC_GROUP_set_asn1_flag((EC_GROUP *)ec_group, 1);
			EC_GROUP_free(builtin);
			break;
		}
		EC_GROUP_free(builtin);
	}
#else
	(void)pkey;
#endif
}

void pki_evp::fload(const QString fname)
{
	pass_info p(XCA_TITLE, tr("Please enter the password to decrypt the private key from file:\n%1").
		arg(compressFilename(fname)));
	pem_password_cb *cb = PwDialog::pwCallback;
	FILE *fp = fopen_read(fname);
	EVP_PKEY *pkey;

	pki_ign_openssl_error();
	if (!fp) {
		fopen_error(fname);
		return;
	}
	pkey = PEM_read_PrivateKey(fp, NULL, cb, &p);
	try {
		openssl_pw_error(fname);
	} catch (errorEx &err) {
		fclose(fp);
		throw err;
	}
	if (!pkey) {
		pki_ign_openssl_error();
		rewind(fp);
		pkey = d2i_PrivateKey_fp(fp, NULL);
	}
	if (!pkey) {
		pki_ign_openssl_error();
		rewind(fp);
		pkey = d2i_PKCS8PrivateKey_fp(fp, NULL, cb, &p);
	}
	if (!pkey) {
		PKCS8_PRIV_KEY_INFO *p8inf;
		pki_ign_openssl_error();
		rewind(fp);
		p8inf = d2i_PKCS8_PRIV_KEY_INFO_fp(fp, NULL);
		if (p8inf) {
			pkey = EVP_PKCS82PKEY(p8inf);
			PKCS8_PRIV_KEY_INFO_free(p8inf);
		}
	}
	if (!pkey) {
		pki_ign_openssl_error();
		rewind(fp);
		pkey = PEM_read_PUBKEY(fp, NULL, cb, &p);
	}
	if (!pkey) {
		pki_ign_openssl_error();
		rewind(fp);
		pkey = d2i_PUBKEY_fp(fp, NULL);
	}
	if (!pkey) {
		pki_ign_openssl_error();
                rewind(fp);
		try {
			pkey = load_ssh2_key(fp);
		} catch (errorEx &err) {
			fclose(fp);
			throw err;
		}
        }
	fclose(fp);
	if (!pkey || pki_ign_openssl_error()) {
		if (pkey)
			EVP_PKEY_free(pkey);
		throw errorEx(tr("Unable to load the private key in file %1. Tried PEM and DER private, public, PKCS#8 key types and SSH2 format.").arg(fname));
	}
	if (pkey){
		search_ec_oid(pkey);
		if (key)
			EVP_PKEY_free(key);
		key = pkey;
		if (EVP_PKEY_isPrivKey(key))
			bogusEncryptKey();
		setIntName(rmslashdot(fname));
	}
}

void pki_evp::fromData(const unsigned char *p, db_header_t *head)
{
	int version, type, size;
	void *ptr = NULL;

	if (key)
		EVP_PKEY_free(key);
	key = NULL;

	size = head->len - sizeof(db_header_t);
	version = head->version;

	QByteArray ba((const char*)p, size);

	type = db::intFromData(ba);
	ownPass = (enum passType)db::intFromData(ba);
	if (version < 2) {
		d2i_old(ba, type);
	} else {
		d2i(ba);
	}
	pki_openssl_error();

	if (key)
		ptr = EVP_PKEY_get0(key);
	if (!ptr)
		throw errorEx(tr("Ignoring unsupported private key"));

	encKey = ba;
	isPub = encKey.size() == 0;
}

EVP_PKEY *pki_evp::decryptKey() const
{
	Passwd ownPassBuf;
	int ret;

	if (isPubKey()) {
		QByteArray ba = i2d_bytearray(I2D_VOID(i2d_PUBKEY), key);
		return (EVP_PKEY*)d2i_bytearray(D2I_VOID(d2i_PUBKEY), ba);
	}
	/* This key has its own password */
	if (ownPass == ptPrivate) {
		pass_info pi(XCA_TITLE, tr("Please enter the password to decrypt the private key: '%1'").arg(getIntName()));
		ret = PwDialog::execute(&pi, &ownPassBuf, false);
		if (ret != 1)
			throw errorEx(tr("Password input aborted"),
					getClassName());
	} else if (ownPass == ptBogus) { // BOGUS pass
		ownPassBuf = "Bogus";
	} else {
		ownPassBuf = passwd;
		while (sha512passwT(ownPassBuf, passHash) != passHash &&
			sha512passwd(ownPassBuf, passHash) != passHash)
		{
			pass_info p(XCA_TITLE, tr("Please enter the database password for decrypting the key '%1'").arg(getIntName()));
			ret = PwDialog::execute(&p, &ownPassBuf, false);
			if (ret != 1)
				throw errorEx(tr("Password input aborted"),
						getClassName());
		}
	}
	QByteArray myencKey = getEncKey();
	qDebug() << "myencKey.count()"<<myencKey.count();
	if (myencKey.count() == 0)
		return NULL;
	BIO *b = BIO_from_QByteArray(myencKey);
	check_oom(b);
	EVP_PKEY *priv = NULL;
	X509_SIG *p8 = d2i_PKCS8_bio(b, NULL);
	if (p8) {
		PKCS8_PRIV_KEY_INFO *p8inf = PKCS8_decrypt(p8,
				ownPassBuf.constData(), ownPassBuf.size());
		if (p8inf) {
			priv = EVP_PKCS82PKEY(p8inf);
			PKCS8_PRIV_KEY_INFO_free(p8inf);
		}
		X509_SIG_free(p8);
	}
	BIO_free(b);
	if (priv)
		return priv;
	pki_ign_openssl_error();
	return legacyDecryptKey(myencKey, ownPassBuf);
}

EVP_PKEY *pki_evp::legacyDecryptKey(QByteArray &myencKey,
				    Passwd &ownPassBuf) const
{
	unsigned char *p;
	const unsigned char *p1;
	int outl, decsize;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char ckey[EVP_MAX_KEY_LENGTH];

	EVP_PKEY *tmpkey;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_CIPHER_CTX ctxbuf;
#endif
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
	p = (unsigned char *)OPENSSL_malloc(myencKey.count());
	check_oom(p);
	pki_openssl_error();
	p1 = p;
	memset(iv, 0, EVP_MAX_IV_LENGTH);

	memcpy(iv, myencKey.constData(), 8); /* recover the iv */
	/* generate the key */
	EVP_BytesToKey(cipher, EVP_sha1(), iv,
		ownPassBuf.constUchar(), ownPassBuf.size(), 1, ckey, NULL);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx = EVP_CIPHER_CTX_new();
#else
	ctx = &ctxbuf;
#endif
	EVP_CIPHER_CTX_init(ctx);
	EVP_DecryptInit(ctx, cipher, ckey, iv);
	EVP_DecryptUpdate(ctx, p , &outl,
		(const unsigned char*)myencKey.constData() +8,
		myencKey.count() -8);
	decsize = outl;
	EVP_DecryptFinal_ex(ctx, p + decsize , &outl);
	EVP_CIPHER_CTX_cleanup(ctx);
	decsize += outl;
	pki_openssl_error();
	tmpkey = d2i_PrivateKey(getKeyType(), NULL, &p1, decsize);
	pki_openssl_error();
	OPENSSL_cleanse(p, myencKey.count());
	OPENSSL_free(p);
	EVP_CIPHER_CTX_cleanup(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_CIPHER_CTX_free(ctx);
#endif
	pki_openssl_error();
	if (EVP_PKEY_type(getKeyType()) == EVP_PKEY_RSA) {
		RSA *rsa = EVP_PKEY_get0_RSA(tmpkey);
		RSA_blinding_on(rsa, NULL);
	}
	myencKey.fill(0);
	return tmpkey;
}

EVP_PKEY *pki_evp::priv2pub(EVP_PKEY* key)
{
	int keylen;
	unsigned char *p, *p1;
	EVP_PKEY *pubkey;

	keylen = i2d_PUBKEY(key, NULL);
	p1 = p = (unsigned char *)OPENSSL_malloc(keylen);
	check_oom(p);

	/* convert rsa/dsa/ec to Pubkey */
	keylen = i2d_PUBKEY(key, &p);
	pki_openssl_error();
	p = p1;
	pubkey = d2i_PUBKEY(NULL, (const unsigned char**)&p, keylen);
	OPENSSL_free(p1);
	pki_openssl_error();
	return pubkey;
}

void pki_evp::encryptKey(const char *password)
{
	Passwd ownPassBuf;

	pki_openssl_error();
	/* This key has its own, private password */
	if (ownPass == ptPrivate) {
		int ret;
		pass_info p(XCA_TITLE, tr("Please enter the password to protect the private key: '%1'").
			arg(getIntName()));
		ret = PwDialog::execute(&p, &ownPassBuf, true);
		if (ret != 1)
			throw errorEx("Password input aborted", getClassName());
	pki_openssl_error();
	} else if (ownPass == ptBogus) { // BOGUS password
		ownPassBuf = "Bogus";
	pki_openssl_error();
	} else {
		if (password) {
			/* use the password parameter
			 * if this is a common password */
			ownPassBuf = password;
	pki_openssl_error();
		} else {
			int ret = 0;
			ownPassBuf = passwd;
			pass_info p(XCA_TITLE, tr("Please enter the database password for encrypting the key"));
			while (sha512passwT(ownPassBuf, passHash) != passHash &&
				sha512passwd(ownPassBuf, passHash) != passHash)
			{
				ret = PwDialog::execute(&p, &ownPassBuf, false);
				if (ret != 1)
					throw errorEx("Password input aborted",
							getClassName());
			}
		}
	}

	/* Convert private key to DER(PKCS8-aes) */
	const char *p;
	BIO *bio = BIO_new(BIO_s_mem());
	i2d_PKCS8PrivateKey_bio(bio, key, EVP_aes_256_cbc(),
		ownPassBuf.data(), ownPassBuf.size(), NULL, 0);
	pki_openssl_error();
	int l = BIO_get_mem_data(bio, &p);
	encKey = QByteArray(p, l);
	BIO_free(bio);

	/* Replace private key by public key and
	   have the encrypted private in "encKey"
	 */
	EVP_PKEY *pkey1 = priv2pub(key);
	check_oom(pkey1);
	EVP_PKEY_free(key);
	key = pkey1;
	pki_openssl_error();
}

void pki_evp::set_evp_key(EVP_PKEY *pkey)
{
	if (key)
		free(key);
	key = pkey;
}

void pki_evp::bogusEncryptKey()
{
	ownPass = ptBogus;
	isPub = false;
	encryptKey();
}

pki_evp::~pki_evp()
{
	encKey.fill(0);
}

QSqlError pki_evp::insertSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_key::insertSqlData();
	if (e.isValid())
		return e;
	if (isPubKey())
		return QSqlError();

	SQL_PREPARE(q, "INSERT INTO private_keys (item, ownPass, private) "
		  "VALUES (?, ?, ?)");
	q.bindValue(0, sqlItemId);
	q.bindValue(1, ownPass);
	q.bindValue(2, encKey_b64());
	q.exec();
	encKey.fill(0);
	encKey.clear();
	return q.lastError();
}

void pki_evp::restoreSql(const QSqlRecord &rec)
{
	pki_key::restoreSql(rec);
	isPub = rec.isNull(VIEW_private_ownpass);
	if (!isPub)
		ownPass =(enum passType)rec.value(VIEW_private_ownpass).toInt();
}

QByteArray pki_evp::getEncKey() const
{
	XSqlQuery q;
	QSqlError e;
	QByteArray ba;

	if (encKey.count() > 0 || !sqlItemId.isValid())
		return encKey;

	SQL_PREPARE(q, "SELECT private FROM private_keys WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	e = q.lastError();
	if (e.isValid() || !q.first())
		return QByteArray();
	return QByteArray::fromBase64(q.value(0).toByteArray().trimmed());
}

QSqlError pki_evp::deleteSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_key::deleteSqlData();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "DELETE FROM private_keys WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	return q.lastError();
}

void pki_evp::writePKCS8(const QString fname, const EVP_CIPHER *enc,
		pem_password_cb *cb, bool pem)
{
	EVP_PKEY *pkey;
	pass_info p(XCA_TITLE, tr("Please enter the password protecting the PKCS#8 key '%1'").arg(getIntName()));
	FILE *fp = fopen_write_key(fname);
	if (fp != NULL) {
		if (key) {
			pkey = decryptKey();
			if (pkey) {
				if (pem)
					PEM_write_PKCS8PrivateKey(fp, pkey, enc, NULL, 0, cb, &p);
				else
					i2d_PKCS8PrivateKey_fp(fp, pkey, enc, NULL, 0, cb, &p);
				EVP_PKEY_free(pkey);
			}
		}
		fclose(fp);
		pki_openssl_error();
	} else
		fopen_error(fname);
}

static int mycb(char *buf, int size, int, void *)
{
	strncpy(buf, pki_evp::passwd, size);
	return strlen(pki_evp::passwd);
}

void pki_evp::writeDefault(const QString fname)
{
	writeKey(get_dump_filename(fname, ".pem"),
		pki_evp::passwd[0] ? EVP_des_ede3_cbc() : NULL,
		mycb, true);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined LIBRESSL_VERSION_NUMBER
int PEM_write_bio_PrivateKey_traditional(BIO *bp, EVP_PKEY *x,
                                         const EVP_CIPHER *enc,
                                         unsigned char *kstr, int klen,
                                         pem_password_cb *cb, void *u)
{
	const char *t = "";
	int keytype = EVP_PKEY_id(x);

	switch (keytype) {
		case EVP_PKEY_RSA: t = "RSA PRIVATE KEY"; break;
		case EVP_PKEY_DSA: t = "DSA PRIVATE KEY"; break;
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC: t = "EC PRIVATE KEY"; break;
#endif
	}
	return PEM_ASN1_write_bio((i2d_of_void *)i2d_PrivateKey,
				t, bp, (char*)x, enc, kstr, klen, cb, u);
}
#endif

void pki_evp::writeKey(const QString fname, const EVP_CIPHER *enc,
			pem_password_cb *cb, bool pem)
{
	pass_info p(XCA_TITLE, tr("Please enter the export password for the private key '%1'").arg(getIntName()));

	if (isPubKey()) {
		writePublic(fname, pem);
		return;
	}
	FILE *fp = fopen_write_key(fname);
	if (!fp) {
		fopen_error(fname);
		return;
	}
	EVP_PKEY *pkey = key ? decryptKey() : NULL;
	if (!pkey) {
		fclose(fp);
	        pki_openssl_error();
		return;
	}
	if (pem) {
		BIO *b = BIO_new_fp(fp, BIO_NOCLOSE);
		if (!b) {
			EVP_PKEY_free(pkey);
			fclose(fp);
			return;
		}
		PEM_write_bio_PrivateKey_traditional(b, pkey, enc,
						NULL, 0, cb, &p);
		BIO_free(b);
	} else {
		i2d_PrivateKey_fp(fp, pkey);
	}
	fclose(fp);
	pki_openssl_error();
	EVP_PKEY_free(pkey);
}

int pki_evp::verify()
{
	bool veri = false;
	return true;
	if (getKeyType() == EVP_PKEY_RSA && isPrivKey()) {
		RSA *rsa = EVP_PKEY_get0_RSA(key);
		if (RSA_check_key(rsa) == 1)
			veri = true;
	}
	if (isPrivKey())
		veri = true;
	pki_openssl_error();
	return veri;
}

QVariant pki_evp::getIcon(const dbheader *hd) const
{
	if (hd->id != HD_internal_name)
		return QVariant();
	int pixnum= isPubKey() ? 1 : 0;
	return QVariant(*icon[pixnum]);
}

QString pki_evp::md5passwd(QByteArray pass)
{

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX mdctxbuf;
#endif
	EVP_MD_CTX *mdctx;
	int n;
	unsigned char m[EVP_MAX_MD_SIZE];

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	mdctx = EVP_MD_CTX_new();
#else
	mdctx = &mdctxbuf;
#endif

	EVP_DigestInit(mdctx, EVP_md5());
	EVP_DigestUpdate(mdctx, pass.constData(), pass.size());
	EVP_DigestFinal(mdctx, m, (unsigned*)&n);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX_free(mdctx);
#endif
	return formatHash(m, n);
}

QString pki_evp::_sha512passwd(QByteArray pass, QString salt,
				int size, int repeat)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX mdctxbuf;
#endif
	EVP_MD_CTX *mdctx;
	QString str;
	int n;
	unsigned char m[EVP_MAX_MD_SIZE];

	if (salt.length() < size) {
		abort();
	}
	str = salt.left(size);
	pass = str.toLatin1() + pass;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	mdctx = EVP_MD_CTX_new();
#else
	mdctx = &mdctxbuf;
#endif
	while (repeat--) {
		EVP_DigestInit(mdctx, EVP_sha512());
		EVP_DigestUpdate(mdctx, pass.constData(), pass.size());
		EVP_DigestFinal(mdctx, m, (unsigned*)&n);
		pass = QByteArray((char*)m, n);

	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX_free(mdctx);
#endif
	return str + formatHash(m, n, false);
}

QString pki_evp::sha512passwd(QByteArray pass, QString salt)
{
	return _sha512passwd(pass, salt, 5, 1);
}

QString pki_evp::sha512passwT(QByteArray pass, QString salt)
{
	return _sha512passwd(pass, salt, 17, 8000);
}
