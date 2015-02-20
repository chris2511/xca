/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_evp.h"
#include "pass_info.h"
#include "Passwd.h"
#include "func.h"
#include "db.h"
#include "entropy.h"
#include "widgets/PwDialog.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <QProgressDialog>
#include <QApplication>
#include <QDir>

Passwd pki_evp::passwd;
Passwd pki_evp::oldpasswd;

QString pki_evp::passHash = QString();

QPixmap *pki_evp::icon[2]= { NULL, NULL };

void pki_evp::init(int type)
{
	key->type = type;
	class_name = "pki_evp";
	ownPass = ptCommon;
	dataVersion=2;
	pkiType=asym_key;
}

QString pki_evp::removeTypeFromIntName(QString n)
{
	if (n.right(1) != ")" )
		return n;
	n.truncate(n.length() - 6);
	return n;
}

void pki_evp::setOwnPass(enum passType x)
{
	EVP_PKEY *pk=NULL, *pk_back = key;
	int oldOwnPass = ownPass;

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
	EVP_PKEY_free(pk_back);
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

	switch (type) {
	case EVP_PKEY_RSA:
		RSA *rsakey;
		rsakey = RSA_generate_key(bits, 0x10001, inc_progress_bar,
			progress);
		if (rsakey)
			EVP_PKEY_assign_RSA(key, rsakey);
		break;
	case EVP_PKEY_DSA:
		DSA *dsakey;
		progress->setMaximum(500);
		dsakey = DSA_generate_parameters(bits, NULL, 0, NULL, NULL,
				inc_progress_bar, progress);
		DSA_generate_key(dsakey);
		if (dsakey)
			EVP_PKEY_assign_DSA(key, dsakey);
		break;
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
	pki_openssl_error();
	encryptKey();
}

pki_evp::pki_evp(const pki_evp *pk)
	:pki_key(pk)
{
	init(pk->key->type);
	pki_openssl_error();
	ownPass = pk->ownPass;
	encKey = pk->encKey;
}

pki_evp::pki_evp(const QString name, int type )
	:pki_key(name)
{
	init(type);
	pki_openssl_error();
}

pki_evp::pki_evp(EVP_PKEY *pkey)
	:pki_key()
{
	init();
	if (key) {
		EVP_PKEY_free(key);
	}
	key = pkey;
}

static bool EVP_PKEY_isPrivKey(EVP_PKEY *key)
{
	switch (EVP_PKEY_type(key->type)) {
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

void pki_evp::openssl_pw_error(QString fname)
{
	switch (ERR_peek_error() & 0xff000fff) {
	case ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_DECRYPT):
	case ERR_PACK(ERR_LIB_PEM, 0, PEM_R_BAD_PASSWORD_READ):
	case ERR_PACK(ERR_LIB_EVP, 0, EVP_R_BAD_DECRYPT):
		pki_ign_openssl_error();
		throw errorEx(tr("Failed to decrypt the key (bad password) ")+
				fname, class_name, E_PASSWD);
	}
}

void pki_evp::fromPEM_BIO(BIO *bio, QString name)
{
	EVP_PKEY *pkey;
	int pos;
	pass_info p(XCA_TITLE,
		tr("Please enter the password to decrypt the private key.") +
		" " + name);
	pos = BIO_tell(bio);
	pkey = PEM_read_bio_PrivateKey(bio, NULL, PwDialog::pwCallback, &p);
	openssl_pw_error(name);
	if (!pkey){
		pki_ign_openssl_error();
		pos = BIO_seek(bio, pos);
		pkey = PEM_read_bio_PUBKEY(bio, NULL, PwDialog::pwCallback, &p);
	}
	if (pkey){
		if (key)
			EVP_PKEY_free(key);
		key = pkey;
		if (EVP_PKEY_isPrivKey(key))
			bogusEncryptKey();
		setIntName(rmslashdot(name));
	}
	openssl_error(name);
}

static void search_ec_oid(EVP_PKEY *pkey)
{
#ifndef OPENSSL_NO_EC
	if (pkey->type != EVP_PKEY_EC)
		return;

	EC_KEY *ec = pkey->pkey.ec;

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

void pki_evp::fromData(const unsigned char *p, db_header_t *head )
{
	int version, type, size;

	if (key)
		EVP_PKEY_free(key);
	key = NULL;

	size = head->len - sizeof(db_header_t);
	version = head->version;

	QByteArray ba((const char*)p, size);

	type = db::intFromData(ba);
	ownPass = db::intFromData(ba);
	if (version < 2) {
		d2i_old(ba, type);
	} else {
		d2i(ba);
	}
	pki_openssl_error();
	if (!key || !key->pkey.ptr) {
		throw errorEx(tr("Ignoring unsupported private key"));
	}
	encKey = ba;
}

EVP_PKEY *pki_evp::decryptKey() const
{
	unsigned char *p;
	const unsigned char *p1;
	int outl, decsize;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char ckey[EVP_MAX_KEY_LENGTH];

	EVP_PKEY *tmpkey;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
	Passwd ownPassBuf;
	int ret;

	if (isPubKey()) {
		unsigned char *q;
		outl = i2d_PUBKEY(key, NULL);
		p = q = (unsigned char *)OPENSSL_malloc(outl);
		check_oom(q);
		i2d_PUBKEY(key, &p);
		p = q;
		tmpkey = d2i_PUBKEY(NULL, (const unsigned char**)&p, outl);
		OPENSSL_free(q);
		return tmpkey;
	}
	/* This key has its own password */
	if (ownPass == ptPrivate) {
		pass_info pi(XCA_TITLE, tr("Please enter the password to decrypt the private key: '%1'").arg(getIntName()));
		ret = PwDialog::execute(&pi, &ownPassBuf, false);
		if (ret != 1)
			throw errorEx(tr("Password input aborted"), class_name);
	} else if (ownPass == ptBogus) { // BOGUS pass
		ownPassBuf = "Bogus";
	} else {
		ownPassBuf = passwd;
		while (md5passwd(ownPassBuf) != passHash &&
			sha512passwd(ownPassBuf, passHash) != passHash)
		{
			pass_info p(XCA_TITLE, tr("Please enter the database password for decrypting the key '%1'").arg(getIntName()));
			ret = PwDialog::execute(&p, &ownPassBuf, false);
			if (ret != 1)
				throw errorEx(tr("Password input aborted"), class_name);
		}
	}
	p = (unsigned char *)OPENSSL_malloc(encKey.count());
	check_oom(p);
	pki_openssl_error();
	p1 = p;
	memset(iv, 0, EVP_MAX_IV_LENGTH);

	memcpy(iv, encKey.constData(), 8); /* recover the iv */
	/* generate the key */
	EVP_BytesToKey(cipher, EVP_sha1(), iv,
		ownPassBuf.constUchar(),
		ownPassBuf.size(), 1, ckey, NULL);
	/* we use sha1 as message digest,
	 * because an md5 version of the password is
	 * stored in the database...
	 */
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit(&ctx, cipher, ckey, iv);
	EVP_DecryptUpdate(&ctx, p , &outl,
		(const unsigned char*)encKey.constData() +8, encKey.count() -8);

	decsize = outl;
	EVP_DecryptFinal(&ctx, p + decsize , &outl);
	decsize += outl;
	//printf("Decrypt decsize=%d, encKey_len=%d\n", decsize, encKey.count() -8);
	pki_openssl_error();
	tmpkey = d2i_PrivateKey(key->type, NULL, &p1, decsize);
	pki_openssl_error();
	OPENSSL_free(p);
	EVP_CIPHER_CTX_cleanup(&ctx);
	pki_openssl_error();
	if (EVP_PKEY_type(tmpkey->type) == EVP_PKEY_RSA)
		RSA_blinding_on(tmpkey->pkey.rsa, NULL);
	return tmpkey;
}

QByteArray pki_evp::toData()
{
	QByteArray ba;

	ba += db::intToData(key->type);
	ba += db::intToData(ownPass);
	ba += i2d();
	ba += encKey;
	return ba;
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
	int outl, keylen;
	EVP_PKEY *pkey1 = NULL;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
	unsigned char iv[EVP_MAX_IV_LENGTH], *punenc, *punenc1;
	unsigned char ckey[EVP_MAX_KEY_LENGTH];
	Passwd ownPassBuf;

	/* This key has its own, private password */
	if (ownPass == ptPrivate) {
		int ret;
		pass_info p(XCA_TITLE, tr("Please enter the password to protect the private key: '%1'").
			arg(getIntName()));
		ret = PwDialog::execute(&p, &ownPassBuf, true);
		if (ret != 1)
			throw errorEx("Password input aborted", class_name);
	} else if (ownPass == ptBogus) { // BOGUS password
		ownPassBuf = "Bogus";
	} else {
		if (password) {
			/* use the password parameter
			 * if this is a common password */
			ownPassBuf = password;
		} else {
			int ret = 0;
			ownPassBuf = passwd;
			pass_info p(XCA_TITLE, tr("Please enter the database password for encrypting the key"));
			while (md5passwd(ownPassBuf) != passHash &&
				sha512passwd(ownPassBuf, passHash) != passHash )
			{
				ret = PwDialog::execute(&p, &ownPassBuf, false);
				if (ret != 1)
					throw errorEx("Password input aborted", class_name);
			}
		}
	}

	/* Prepare Encryption */
	memset(iv, 0, EVP_MAX_IV_LENGTH);
	Entropy::get(iv, 8);      /* Generate a salt */
	EVP_BytesToKey(cipher, EVP_sha1(), iv,
			ownPassBuf.constUchar(),
			ownPassBuf.size(), 1, ckey, NULL);
	EVP_CIPHER_CTX_init (&ctx);
	pki_openssl_error();

	/* reserve space for unencrypted and encrypted key */
	keylen = i2d_PrivateKey(key, NULL);
	encKey.resize(keylen + EVP_MAX_KEY_LENGTH + 8);
	punenc1 = punenc = (unsigned char *)OPENSSL_malloc(keylen);
	check_oom(punenc);
	keylen = i2d_PrivateKey(key, &punenc1);
	pki_openssl_error();

	memcpy(encKey.data(), iv, 8); /* store the iv */
	/*
	 * Now DER version of privkey is in punenc
	 * and privkey is still in key
	 */

	/* do the encryption */
	/* store key right after the iv */
	EVP_EncryptInit(&ctx, cipher, ckey, iv);
	unsigned char *penc = (unsigned char *)encKey.data() +8;
	EVP_EncryptUpdate(&ctx, penc, &outl, punenc, keylen);
	int encKey_len = outl;
	EVP_EncryptFinal(&ctx, penc + encKey_len, &outl);
	encKey.resize(encKey_len + outl +8);
	/* Cleanup */
	EVP_CIPHER_CTX_cleanup(&ctx);
	/* wipe out the memory */
	memset(punenc, 0, keylen);
	OPENSSL_free(punenc);
	pki_openssl_error();

	pkey1 = priv2pub(key);
	check_oom(pkey1);
	EVP_PKEY_free(key);
	key = pkey1;
	pki_openssl_error();

	//CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF);

	//printf("Encrypt: encKey_len=%d\n", encKey_len);
	return;
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
	encryptKey();
}

pki_evp::~pki_evp()
{
}


void pki_evp::writePKCS8(const QString fname, const EVP_CIPHER *enc,
		pem_password_cb *cb, bool pem)
{
	EVP_PKEY *pkey;
	pass_info p(XCA_TITLE, tr("Please enter the password protecting the PKCS#8 key '%1'").arg(getIntName()));
	FILE *fp = fopen_write(fname);
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
	writeKey(fname + QDir::separator() + getIntName() + ".pem",
			EVP_des_ede3_cbc(), mycb, true);
}

void pki_evp::writeKey(const QString fname, const EVP_CIPHER *enc,
			pem_password_cb *cb, bool pem)
{
	EVP_PKEY *pkey;
	pass_info p(XCA_TITLE, tr("Please enter the export password for the private key '%1'").arg(getIntName()));
	if (isPubKey()) {
		writePublic(fname, pem);
		return;
	}
	FILE *fp = fopen_write(fname);
	if (!fp) {
		fopen_error(fname);
		return;
	}
	if (key){
		pkey = decryptKey();
		if (pkey) {
			if (pem) {
				switch (pkey->type) {
				case EVP_PKEY_RSA:
					PEM_write_RSAPrivateKey(fp,
					  pkey->pkey.rsa, enc, NULL, 0, cb, &p);
					break;
				case EVP_PKEY_DSA:
					PEM_write_DSAPrivateKey(fp,
					  pkey->pkey.dsa, enc, NULL, 0, cb, &p);
					break;
#ifndef OPENSSL_NO_EC
				case EVP_PKEY_EC:
					PEM_write_ECPrivateKey(fp,
					  pkey->pkey.ec, enc, NULL, 0, cb, &p);
					break;
#endif
				default:
					PEM_write_PrivateKey(fp, pkey,
							enc, NULL, 0, cb, &p);
				}
			} else {
				i2d_PrivateKey_fp(fp, pkey);
			}
			EVP_PKEY_free(pkey);
		}
		pki_openssl_error();
	}
	fclose(fp);
}

bool pki_evp::isPubKey() const
{
	if (encKey.count() == 0) {
		return true;
	}
	return false;
}

int pki_evp::verify()
{
	bool veri = false;
	return true;
	if (key->type == EVP_PKEY_RSA && isPrivKey()) {
		if (RSA_check_key(key->pkey.rsa) == 1)
			veri = true;
	}
	if (isPrivKey())
		veri = true;
	pki_openssl_error();
	return veri;
}

const EVP_MD *pki_evp::getDefaultMD()
{
	const EVP_MD *md;
	switch (key->type) {
		case EVP_PKEY_RSA: md = EVP_sha1(); break;
		case EVP_PKEY_DSA: md = EVP_dss1(); break;
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:  md = EVP_ecdsa(); break;
#endif
		default: md = NULL; break;
	}
	return md;
}

QVariant pki_evp::getIcon(dbheader *hd)
{
	if (hd->id != HD_internal_name)
		return QVariant();
	int pixnum= isPubKey() ? 1 : 0;
	return QVariant(*icon[pixnum]);
}

QString pki_evp::md5passwd(QByteArray pass)
{

	EVP_MD_CTX mdctx;
	QString str;
	int n;
	int j;
	unsigned char m[EVP_MAX_MD_SIZE];
	EVP_DigestInit(&mdctx, EVP_md5());
	EVP_DigestUpdate(&mdctx, pass.constData(), pass.size());
	EVP_DigestFinal(&mdctx, m, (unsigned*)&n);
	for (j=0; j<n; j++) {
		char zs[4];
		sprintf(zs, "%02X%c",m[j], (j+1 == n) ?'\0':':');
		str += zs;
	}
	return str;
}

QString pki_evp::sha512passwd(QByteArray pass, QString salt)
{

	EVP_MD_CTX mdctx;
	QString str;
	int n;
	int j;
	unsigned char m[EVP_MAX_MD_SIZE];

	if (salt.length() <5)
		abort();

	str = salt.left(5);
	pass = str.toLatin1() + pass;

	EVP_DigestInit(&mdctx, EVP_sha512());
	EVP_DigestUpdate(&mdctx, pass.constData(), pass.size());
	EVP_DigestFinal(&mdctx, m, (unsigned*)&n);

	for (j=0; j<n; j++) {
		char zs[4];
		sprintf(zs, "%02X",m[j]);
		str += zs;
	}
	return str;
}

void pki_evp::veryOldFromData(unsigned char *p, int size )
{
	unsigned char *sik, *pdec, *pdec1, *sik1;
	int outl, decsize;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char ckey[EVP_MAX_KEY_LENGTH];
	memset(iv, 0, EVP_MAX_IV_LENGTH);
	RSA *rsakey;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
	sik = (unsigned char *)OPENSSL_malloc(size);
	check_oom(sik);
	pki_openssl_error();
	pdec = (unsigned char *)OPENSSL_malloc(size);
	if (pdec == NULL ) {
		OPENSSL_free(sik);
		check_oom(pdec);
	}
	pdec1=pdec;
	sik1=sik;
	memcpy(iv, p, 8); /* recover the iv */
	/* generate the key */
	EVP_BytesToKey(cipher, EVP_sha1(), iv, oldpasswd.constUchar(),
		oldpasswd.size(), 1, ckey, NULL);
	/* we use sha1 as message digest,
	 * because an md5 version of the password is
	 * stored in the database...
	 */
	EVP_CIPHER_CTX_init (&ctx);
	EVP_DecryptInit( &ctx, cipher, ckey, iv);
	EVP_DecryptUpdate( &ctx, pdec , &outl, p + 8, size -8 );
	decsize = outl;
	EVP_DecryptFinal( &ctx, pdec + decsize , &outl );
	decsize += outl;
	pki_openssl_error();
	memcpy(sik, pdec, decsize);
	if (key->type == EVP_PKEY_RSA) {
		rsakey=d2i_RSAPrivateKey(NULL,(const unsigned char **)&pdec, decsize);
		if (pki_ign_openssl_error()) {
			rsakey = d2i_RSA_PUBKEY(NULL, (const unsigned char **)&sik, decsize);
		}
		pki_openssl_error();
		if (rsakey) EVP_PKEY_assign_RSA(key, rsakey);
	}
	OPENSSL_free(sik1);
	OPENSSL_free(pdec1);
	EVP_CIPHER_CTX_cleanup(&ctx);
	pki_openssl_error();
	encryptKey();
}

void pki_evp::oldFromData(unsigned char *p, int size )
{
	int version, type;

	QByteArray ba;

	version = intFromData(ba);
	if (version != 1) { // backward compatibility
		veryOldFromData(p, size);
		return;
	}
	if (key)
		EVP_PKEY_free(key);

	key = NULL;
	type = intFromData(ba);
	ownPass = intFromData(ba);

	d2i_old(ba, type);
	pki_openssl_error();

	encKey = ba;
}

