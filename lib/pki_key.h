/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef PKI_KEY_H
#define PKI_KEY_H

#include <qstring.h>
#include <qprogressbar.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "pki_base.h"

#define MAX_KEY_LENGTH 4096
#define MAX_PASS_LENGTH 40

class pki_key: public pki_base
{

	protected:
		int ownPass;
		EVP_PKEY *key;
		unsigned char *encKey;
		int encKey_len;
		int ucount; // usage counter
		QString BN2QString(BIGNUM *bn);
		void init(int type = EVP_PKEY_RSA);
		static void incProgress(int a, int b, void *progress);
		void veryOldFromData(unsigned char *p, int size);
	public:
		enum passType { ptCommon, ptPrivate, ptBogus };
		static QPixmap *icon[2];
		static QString passHash;
		static char passwd[MAX_PASS_LENGTH];
		static char oldpasswd[MAX_PASS_LENGTH];
		static void erasePasswd();
		static void eraseOldPasswd();
		static void setPasswd(const char *pass);
		static void setOldPasswd(const char *pass);
		static QString md5passwd(const char *pass,
				char *md5 = NULL, int *len = NULL);
		void generate(int bits, int type, QProgressBar *progress);
		void setOwnPass(enum passType);
		int getOwnPass(void) {return ownPass;};
		pki_key(const QString name = "", int type = EVP_PKEY_RSA);
		pki_key(EVP_PKEY *pkey);
		void encryptKey(const char *password = NULL);
		void bogusEncryptKey();
		EVP_PKEY *decryptKey() const;
		pki_key(const pki_key *pk);
		/* destructor */
		~pki_key();

		QString getTypeString(void);
		QString getIntNameWithType(void);
		static QString removeTypeFromIntName(QString n);
		void fromPEM_BIO(BIO *bio, QString name);
		void fload(const QString fname);
		void writeDefault(const QString fname);
		void fromData(const unsigned char *p, db_header_t *head);
		void oldFromData(unsigned char *p, int size);
		unsigned char *toData(int *size);
		bool compare(pki_base *ref);
		QString length();
		QString modulus();
		QString pubEx();
		QString subprime();
		QString pubkey();
		void writeKey(const QString fname, const EVP_CIPHER *enc,
		pem_password_cb *cb, bool pem);
		void writePublic(const QString fname, bool pem);
		void writePKCS8(const QString fname, const EVP_CIPHER *enc,
		pem_password_cb *cb, bool pem);
		bool isPrivKey() const;
		bool isPubKey() const;
		int verify();
		int getType();
		int incUcount();
		int decUcount();
		int getUcount();
		const EVP_MD *getDefaultMD();
		QVariant column_data(int col);
		EVP_PKEY *getPubKey() {return key;};
		QVariant getIcon();
};

#endif
