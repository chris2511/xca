/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_EVP_H
#define __PKI_EVP_H

#include <QString>
#include <QProgressBar>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "pki_key.h"
#include "Passwd.h"

#define VIEW_private_ownpass 9

class pass_info;

class pki_evp: public pki_key
{
		Q_OBJECT
		QByteArray encKey;
		void init();
		QByteArray getEncKey() const;
		QString encKey_b64()
		{
			return QString::fromLatin1(encKey.toBase64());
		}
		static QString _sha512passwd(QByteArray pass, QString salt,
						int size, int repeat);
		void set_EVP_PKEY(EVP_PKEY *pkey, QString name = QString());

	protected:
		bool openssl_pw_error() const;
	public:
		static QString passHash;
		static Passwd passwd;
		static Passwd oldpasswd;
		static QString md5passwd(QByteArray pass);
		static QString sha512passwd(QByteArray pass, QString salt);
		static QString sha512passwT(QByteArray pass, QString salt);

		pki_evp(const QString &n = QString(), int type = EVP_PKEY_RSA);
		pki_evp(const pki_evp *pkey);
		pki_evp(EVP_PKEY *pkey);
		virtual ~pki_evp();

		void generate(const keyjob &task);
		void setOwnPass(enum passType);
		void set_evp_key(EVP_PKEY *pkey);
		void encryptKey(const char *password = NULL);
		void bogusEncryptKey();
		EVP_PKEY *decryptKey() const;
		EVP_PKEY *legacyDecryptKey(QByteArray &myencKey,
					   Passwd &ownPassBuf) const;
		EVP_PKEY *priv2pub(EVP_PKEY* key);
		static QString removeTypeFromIntName(QString n);
		void fromPEMbyteArray(const QByteArray &ba, const QString &name);
		void fload(const QString &fname);
		EVP_PKEY *load_ssh_ed25519_privatekey(const QByteArray &ba,
						const pass_info &p);
		void writeDefault(const QString &dirname) const;
		void fromData(const unsigned char *p, db_header_t *head);
		void writeKey(XFile &file, const EVP_CIPHER *enc,
				pem_password_cb *cb, bool pem) const;
		void writePKCS8(XFile &file, const EVP_CIPHER *enc,
				pem_password_cb *cb, bool pem) const;
		void writePVKprivate(XFile &file, pem_password_cb *cb) const;
		bool verify_priv(EVP_PKEY *pkey) const;
		QVariant getIcon(const dbheader *hd) const;
		bool sqlUpdatePrivateKey();
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
};

#endif
