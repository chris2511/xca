/*
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_KEY_H
#define __PKI_KEY_H

#include <QString>
#include <QProgressBar>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "pki_base.h"
#include "builtin_curves.h"

#define MAX_KEY_LENGTH 4096

class pki_key: public pki_base
{
		Q_OBJECT
	protected:
		int ownPass, key_size;
		bool isPub;
		EVP_PKEY *key;
		QString BN2QString(const BIGNUM *bn) const;
		QString BNoneLine(BIGNUM *bn) const;
		QByteArray SSH2publicQByteArray();

	private:
		BIGNUM *ssh_key_data2bn(QByteArray *ba, bool skip = false);
		void ssh_key_QBA2data(QByteArray &ba, QByteArray *data);
		void ssh_key_bn2data(const BIGNUM *bn, QByteArray *data);
		int ucount; // usage counter
	public:
		pki_key(const QString name = "");
		pki_key(const pki_key *pk);
		virtual ~pki_key();
		const char *getClassName() const;
		static builtin_curves builtinCurves;
		enum passType { ptCommon, ptPrivate, ptBogus, ptPin };
		QString length() const;
		QString comboText() const;
		virtual EVP_PKEY *decryptKey(int oldkey=0) const;
		virtual const EVP_MD *getDefaultMD();
		virtual bool isToken();
		virtual QString getTypeString(void) const;
		virtual QList<int> possibleHashNids();
		virtual QString getMsg(msg_type msg);

		void writePublic(const QString fname, bool pem);
		bool compare(pki_base *ref);
		int getKeyType() const;
		bool isPrivKey() const;
		int getUcount();
		int getOwnPass(void)
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
		BIO *pem(BIO *, int);
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
		EVP_PKEY *load_ssh2_key(FILE *fp);
		void writeSSH2public(QString fname);
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		QSqlError restoreSql(QVariant sqlId);
};

#endif
