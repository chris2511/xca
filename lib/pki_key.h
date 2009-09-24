/*
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
	private:
		int ucount; // usage counter
	public:
		pki_key(const QString name = "");
		pki_key(const pki_key *pk);
		virtual ~pki_key() { };
		enum passType { ptCommon, ptPrivate, ptBogus, ptPin };

		virtual EVP_PKEY *decryptKey() const { return NULL; };
		virtual QString getTypeString(void) { return QString(); };
		virtual QString length() const { return QString(); };
		virtual bool isPubKey() const { return true; };
		virtual const EVP_MD *getDefaultMD() { return NULL; };
		virtual EVP_PKEY *getPubKey() { return NULL; };
		virtual bool isScard();
		virtual QString length() { return tr("Unknown"); };

		QString getIntNameWithType(void);
		static QString removeTypeFromIntName(QString n);
		bool isPrivKey() const;
		int incUcount();
		int decUcount();
		int getUcount();
		int getOwnPass(void) {return ownPass;};
		QVariant column_data(int col);
};

#endif
