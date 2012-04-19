/*
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_KEY_H
#define __PKI_KEY_H

#include <QtCore/QString>
#include <QtGui/QProgressBar>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "pki_base.h"

#define MAX_KEY_LENGTH 4096

class pki_key: public pki_base
{
		Q_OBJECT
	protected:
		int ownPass;
		EVP_PKEY *key;
		QString BN2QString(BIGNUM *bn) const;
		QString BNoneLine(BIGNUM *bn) const;

	private:
		int ucount; // usage counter
	public:
		pki_key(const QString name = "");
		pki_key(const pki_key *pk);
		virtual ~pki_key();
		enum passType { ptCommon, ptPrivate, ptBogus, ptPin };

		virtual EVP_PKEY *decryptKey() const
		{
			return NULL;
		}
		virtual QString length() const
		{
			return QString();
		}
		virtual bool isPubKey() const
		{
			return true;
		}
		virtual const EVP_MD *getDefaultMD()
		{
			return NULL;
		}
		virtual bool isToken();
		virtual QString getTypeString(void);
		virtual QString getIntNameWithType(void);
		virtual QList<int> possibleHashNids()
		{
			return QList<int>();
		}
		virtual QString getMsg(msg_type msg);
		virtual QString length();

		void writePublic(const QString fname, bool pem);
		bool compare(pki_base *ref);
		int getKeyType();
		static QString removeTypeFromIntName(QString n);
		bool isPrivKey() const;
		int incUcount();
		int decUcount();
		int getUcount();
		int getOwnPass(void)
		{
			return ownPass;
		}
		EVP_PKEY *getPubKey()
		{
			return key;
		}
		QVariant column_data(dbheader *hd);
		QString modulus();
		QString pubEx();
		QString subprime();
		QString pubkey();
		int ecParamNid();
		QString ecPubKey();
		void d2i(QByteArray &ba);
		void d2i_old(QByteArray &ba, int type);
		QByteArray i2d();
};

#endif
