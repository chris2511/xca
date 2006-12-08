/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 *	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 *
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */

#ifndef PKI_KEY_H
#define PKI_KEY_H

#include <Qt/qstring.h>
#include <Qt/qprogressbar.h>
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
