/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_EVP_H
#define __PKI_EVP_H

#include <QString>
#include <QProgressBar>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "pki_key.h"
#include "Passwd.h"

#define VIEW_private_ownpass 9

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
		void set_EVP_PKEY(EVP_PKEY *pkey);

	protected:
		void openssl_pw_error(QString fname);
	public:
		static QPixmap *icon[2];
		static QString passHash;
		static Passwd passwd;
		static Passwd oldpasswd;
		static QString md5passwd(QByteArray pass);
		static QString sha512passwd(QByteArray pass, QString salt);
		static QString sha512passwT(QByteArray pass, QString salt);
		void generate(int bits, int type, QProgressBar *progress);
		void generate(int bits, int type, QProgressBar *progress,
				int curve_nid);
		void setOwnPass(enum passType);
		pki_evp(const QString name = "", int type = EVP_PKEY_RSA);
		pki_evp(EVP_PKEY *pkey);
		void set_evp_key(EVP_PKEY *pkey);
		void encryptKey(const char *password = NULL);
		void bogusEncryptKey();
		EVP_PKEY *decryptKey() const;
		EVP_PKEY *legacyDecryptKey(QByteArray &myencKey,
					   Passwd &ownPassBuf) const;
		pki_evp(const pki_evp *pk);
		/* destructor */
		virtual ~pki_evp();

		EVP_PKEY *priv2pub(EVP_PKEY* key);
		static QString removeTypeFromIntName(QString n);
		void fromPEMbyteArray(QByteArray &ba, QString name);
		void fload(const QString fname);
		void writeDefault(const QString fname);
		void fromData(const unsigned char *p, db_header_t *head);
		void writeKey(const QString fname, const EVP_CIPHER *enc,
		pem_password_cb *cb, bool pem);
		void writePKCS8(const QString fname, const EVP_CIPHER *enc,
		pem_password_cb *cb, bool pem);
		int verify();
		QVariant getIcon(const dbheader *hd) const;
		bool sqlUpdatePrivateKey();
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
};

#endif
