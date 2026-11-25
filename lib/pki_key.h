/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_KEY_H
#define __PKI_KEY_H

#include <QString>
#include <QJsonObject>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "pki_base.h"
#include "builtin_curves.h"

#define PEM_STRING_OPENSSH_KEY "OPENSSH PRIVATE KEY"
#define DEFAULT_KEY_LENGTH 2048
#define ED25519_KEYLEN 32

#define VIEW_public_keys_type 6
#define VIEW_public_keys_len 7
#define VIEW_public_keys_public 8

extern builtin_curves builtinCurves;

/* Post quantum algorithms are provider based only and have no legacy
 * EVP_PKEY_id. They are identified by their OpenSSL algorithm name. */
static inline bool isPqcAlgName(const QString &name)
{
	return name.startsWith("ML-DSA-") || name.startsWith("ML-KEM-") ||
		name.startsWith("SLH-DSA-");
}

/* ML-DSA and SLH-DSA are pure signature algorithms (no pre-hash),
 * while ML-KEM is a key encapsulation algorithm without signature. */
static inline bool isPqcSignatureName(const QString &name)
{
	return name.startsWith("ML-DSA-") || name.startsWith("SLH-DSA-");
}

/* ML-KEM is a key encapsulation mechanism and provides no signature
 * operation at all. */
static inline bool isPqcKemName(const QString &name)
{
	return name.startsWith("ML-KEM-");
}

/* Only the lattice based ML-DSA (FIPS 204) and ML-KEM (FIPS 203)
 * private keys can be stored as seed-only, as expanded key or as both
 * (RFC 9881, RFC 9935). SLH-DSA (FIPS 205) has no such choice. */
static inline bool isPqcSeedName(const QString &name)
{
	return name.startsWith("ML-DSA-") || name.startsWith("ML-KEM-");
}

class keytype
{
  public:
	static QList<keytype> types()
	{
		return QList<keytype> {
			keytype(EVP_PKEY_RSA, "RSA", CKM_RSA_PKCS_KEY_PAIR_GEN,
				false, true),
			keytype(EVP_PKEY_DSA, "DSA", CKM_DSA_KEY_PAIR_GEN,
				false, true),
#ifndef OPENSSL_NO_EC
			keytype(EVP_PKEY_EC, "EC", CKM_EC_KEY_PAIR_GEN,
				true, false),
#ifdef EVP_PKEY_ED25519
			keytype(EVP_PKEY_ED25519, "ED25519", CKM_VENDOR_DEFINED, false, false),
#endif
#endif
#if defined(EVP_PKEY_ML_DSA_44) && defined(EVP_PKEY_ML_DSA_65) && \
	defined(EVP_PKEY_ML_DSA_87)
			keytype(EVP_PKEY_ML_DSA_44, "ML-DSA-44",
				CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_ML_DSA_65, "ML-DSA-65",
				CKM_VENDOR_DEFINED, false, false),
			keytype(EVP_PKEY_ML_DSA_87, "ML-DSA-87",
				CKM_VENDOR_DEFINED, false, false),
#endif
#if defined(NID_ML_KEM_512) && defined(NID_ML_KEM_768) && \
	defined(NID_ML_KEM_1024)
			keytype(NID_ML_KEM_512, "ML-KEM-512",
				CKM_VENDOR_DEFINED, false, false),
			keytype(NID_ML_KEM_768, "ML-KEM-768",
				CKM_VENDOR_DEFINED, false, false),
			keytype(NID_ML_KEM_1024, "ML-KEM-1024",
				CKM_VENDOR_DEFINED, false, false),
#endif
			/* SLH-DSA: FIPS 205 defines 12 parameter sets.
			 * "s" (small signature, slow signing) and
			 * "f" (fast signing, bigger signature) */
#ifdef EVP_PKEY_SLH_DSA_SHA2_128S
			keytype(EVP_PKEY_SLH_DSA_SHA2_128S, "SLH-DSA-SHA2-128s",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_128F
			keytype(EVP_PKEY_SLH_DSA_SHA2_128F, "SLH-DSA-SHA2-128f",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_192S
			keytype(EVP_PKEY_SLH_DSA_SHA2_192S, "SLH-DSA-SHA2-192s",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_192F
			keytype(EVP_PKEY_SLH_DSA_SHA2_192F, "SLH-DSA-SHA2-192f",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_256S
			keytype(EVP_PKEY_SLH_DSA_SHA2_256S, "SLH-DSA-SHA2-256s",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHA2_256F
			keytype(EVP_PKEY_SLH_DSA_SHA2_256F, "SLH-DSA-SHA2-256f",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_128S
			keytype(EVP_PKEY_SLH_DSA_SHAKE_128S, "SLH-DSA-SHAKE-128s",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_128F
			keytype(EVP_PKEY_SLH_DSA_SHAKE_128F, "SLH-DSA-SHAKE-128f",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_192S
			keytype(EVP_PKEY_SLH_DSA_SHAKE_192S, "SLH-DSA-SHAKE-192s",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_192F
			keytype(EVP_PKEY_SLH_DSA_SHAKE_192F, "SLH-DSA-SHAKE-192f",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_256S
			keytype(EVP_PKEY_SLH_DSA_SHAKE_256S, "SLH-DSA-SHAKE-256s",
				CKM_VENDOR_DEFINED, false, false),
#endif
#ifdef EVP_PKEY_SLH_DSA_SHAKE_256F
			keytype(EVP_PKEY_SLH_DSA_SHAKE_256F, "SLH-DSA-SHAKE-256f",
				CKM_VENDOR_DEFINED, false, false),
#endif
		};
	}
	int type{};
	QString name{};
	CK_MECHANISM_TYPE mech{};
	bool curve{}, length{};

	keytype(int t, const QString &n, CK_MECHANISM_TYPE m, bool c, bool l)
			: type(t), name(n), mech(m), curve(c), length(l) { }
	keytype() : type(-1), name(QString()), mech(0),
			curve(false), length(true) { }
	bool isValid()
	{
		return type != -1;
	}
	bool isPqc() const
	{
		return isPqcAlgName(name);
	}
	QString traditionalPemName() const
	{
		/* Provider based PQC keys have no traditional PEM format.
		 * An empty name makes the writer fall back to PKCS#8. */
		if (name.isEmpty() || isPqc())
			return QString();
		return
#ifdef EVP_PKEY_ED25519
			type == EVP_PKEY_ED25519 ? QString("PRIVATE KEY") :
#endif
				QString("%1 PRIVATE KEY").arg(name);
	}
	static const keytype byType(int type)
	{
		foreach(const keytype t, types()) {
			if (t.type == type)
				return t;
		}
		return keytype();
	}
	static const keytype byMech(CK_MECHANISM_TYPE mech)
	{
		foreach(const keytype t, types()) {
			if (t.mech == mech)
				return t;
		}
		return keytype();
	}
	static const keytype byName(const QString &name)
	{
		/* Case insensitive, because PQC algorithm names like
		 * "SLH-DSA-SHA2-128s" are not all upper case */
		foreach(const keytype t, types()) {
			if (!t.name.compare(name, Qt::CaseInsensitive))
				return t;
		}
		return keytype();
	}
	static const keytype byPKEY(EVP_PKEY *pkey)
	{
		keytype kt = byType(EVP_PKEY_type(EVP_PKEY_id(pkey)));

		/* Provider based keys (ML-DSA, ML-KEM, SLH-DSA) have no
		 * legacy EVP_PKEY_id and are identified by their name */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
		if (!kt.isValid() && pkey) {
			const char *alg = EVP_PKEY_get0_type_name(pkey);
			if (alg)
				kt = byName(QString::fromLatin1(alg));
		}
#endif
		return kt;
	}
};

class keyjob
{
  public:
	static keyjob defaultjob;
	keytype ktype;
	int size;
	int ec_nid;
	slotid slot;
	keyjob() {
		size = DEFAULT_KEY_LENGTH;
		ktype = keytype::byName("RSA");
		ec_nid = NID_undef;
		slot = slotid();
	}
	keyjob(const QString &desc)
	{
		QStringList sl = desc.split(':');
		if (sl.size() == 1)
			sl += "";
		if (sl.size() != 2)
			return;
		ktype = keytype::byName(sl[0]);
		size = DEFAULT_KEY_LENGTH;
		ec_nid = NID_undef;
		if (isEC())
			ec_nid = OBJ_txt2nid(sl[1].toLatin1());
		else if (!isED25519() && !isPqc())
			size = sl[1].toInt();
		slot = slotid();
		ign_openssl_error();
	}
	QString toString()
	{
		if (isED25519() || isPqc())
			return ktype.name;
		return QString("%1:%2").arg(ktype.name) .arg(isEC() ?
					OBJ_obj2QString(OBJ_nid2obj(ec_nid)) :
					QString::number(size));
	}
	bool isToken() const
	{
		return slot.lib != NULL;
	}
	bool isEC() const
	{
		return ktype.type == EVP_PKEY_EC;
	}
	bool isED25519() const
	{
#ifdef EVP_PKEY_ED25519
		return ktype.type == EVP_PKEY_ED25519;
#else
		return false;
#endif
	}
	bool isPqc() const
	{
		return ktype.isPqc();
	}
	bool isValid()
	{
		if (!ktype.isValid())
			return false;
		if (isED25519() || isPqc())
			return true;
		if (isEC() && builtinCurves.containNid(ec_nid))
			return true;
		if (!isEC() && size > 0)
			return true;
		return false;
	}
};

class pki_key: public pki_base
{

		Q_OBJECT
	friend class pki_x509super;

	public:
		enum passType { ptCommon, ptPrivate, ptBogus, ptPin };

	protected:
		enum passType ownPass;
		int key_size;
		bool isPub;
		EVP_PKEY *key;
		QString BN2QString(const BIGNUM *bn) const;
		QByteArray SSH2publicQByteArray(bool raw=false) const;
		QByteArray X509_PUBKEY_public_key() const;
		QByteArray PEM_comment() const;
		void collect_properties(QMap<QString, QString> &prp) const;

		BIGNUM *ssh_key_data2bn(QByteArray *ba) const;
		void ssh_key_check_chunk(QByteArray *ba, const char *expect) const;
		QByteArray ssh_key_next_chunk(QByteArray *ba) const;
		void ssh_key_QBA2data(const QByteArray &ba,
					QByteArray *data) const;
		void ssh_key_bn2data(const BIGNUM *bn, QByteArray *data) const;

	private:
		mutable int useCount; // usage counter

	public:

		pki_key(const QString &name = QString());
		pki_key(const pki_key *pk);
		virtual ~pki_key();

		void autoIntName(const QString &file);
		QString length() const;
		QString comboText() const;
		QString getKeyTypeString(void) const;
		bool isPostQuantum() const;
		bool hasSeedFormat() const;
		bool supportsSigning() const;
		bool requiresNullDigest() const;
		const EVP_MD *signingDigest(const EVP_MD *md) const;
		QByteArray rawPubKey() const;
		virtual EVP_PKEY *decryptKey() const = 0;
		virtual bool isToken();
		virtual QString getTypeString(void) const;
		virtual QList<int> possibleHashNids();
		QString getMsg(msg_type msg, int n = 1) const;

		void writePublic(XFile &file, bool pem) const;
		QString getJWKcrv() const;
		void fillJWK(QJsonObject &json, const pki_export *xport) const;
		bool compare(const pki_base *ref) const;
		int getKeyType() const;
		bool isPrivKey() const;
		virtual bool verify(EVP_PKEY *pkey) const;
		int getUcount() const;
		void setUcount(int c)
		{
			useCount = c;
		}
		enum passType getOwnPass(void)
		{
			return ownPass;
		}
		EVP_PKEY *getPubKey()
		{
			return key;
		}
		bool isPubKey() const
		{
			return isPub;
		}
		virtual void generate(const keyjob &)
		{
			qFatal("generate in pki_key");
		}
		bool pem(BioByteArray &);
		virtual bool pem(BioByteArray &b, const pki_export *xport);
		QVariant column_data(const dbheader *hd) const;
		QString modulus() const;
		QString pubEx() const;
		QString subprime() const;
		QString pubkey() const;

#ifndef OPENSSL_NO_EC
		int ecParamNid() const;
		QString ecPubKey() const;
		QByteArray ed25519PubKey() const;
		QByteArray ed25519PrivKey(const EVP_PKEY *pkey) const;
		BIGNUM *ecPubKeyBN() const;
#endif
		void d2i(QByteArray &ba);
		void d2i_old(QByteArray &ba, int type);
		QByteArray i2d() const;
		EVP_PKEY *load_ssh2_key(const QByteArray &ba);
		void writeSSH2public(XFile &file) const;
		QString fingerprint(const QString &format) const;
		bool SSH2_compatible() const;
		void print(BioByteArray &b, enum print_opt opt) const;
		void resetUcount()
		{
			useCount = -1;
		}
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
};

Q_DECLARE_METATYPE(pki_key *);
#endif
