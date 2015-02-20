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

class pki_evp: public pki_key
{
		Q_OBJECT
	protected:
		QByteArray encKey;
		void init(int type = EVP_PKEY_RSA);
		void veryOldFromData(unsigned char *p, int size);
		void openssl_pw_error(QString fname);
	public:
		static QPixmap *icon[2];
		static QString passHash;
		static Passwd passwd;
		static Passwd oldpasswd;
		static QString md5passwd(QByteArray pass);
		static QString sha512passwd(QByteArray pass, QString salt);
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
		pki_evp(const pki_evp *pk);
		/* destructor */
		virtual ~pki_evp();

		EVP_PKEY *priv2pub(EVP_PKEY* key);
		static QString removeTypeFromIntName(QString n);
		void fromPEM_BIO(BIO *bio, QString name);
		void fload(const QString fname);
		void writeDefault(const QString fname);
		void fromData(const unsigned char *p, db_header_t *head);
		void oldFromData(unsigned char *p, int size);
		QByteArray toData();
		void writeKey(const QString fname, const EVP_CIPHER *enc,
		pem_password_cb *cb, bool pem);
		void writePKCS8(const QString fname, const EVP_CIPHER *enc,
		pem_password_cb *cb, bool pem);
		bool isPubKey() const;
		int verify();
		const EVP_MD *getDefaultMD();
		QVariant getIcon(dbheader *hd);
};

#endif
