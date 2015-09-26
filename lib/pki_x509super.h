/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_X509SUPER_H
#define __PKI_X509SUPER_H

#include <openssl/x509.h>
#include <openssl/pem.h>
#include "pki_key.h"
#include "x509name.h"
#include "x509v3ext.h"

class pki_x509name : public pki_base
{
    public:
	pki_x509name(const QString name = "");
	virtual x509name getSubject() const
	{
		return x509name();
	};
	void autoIntName();
	QVariant column_data(dbheader *hd);
	bool visible();
};

class pki_x509super : public pki_x509name
{
		Q_OBJECT
	protected:
		QVariant keySqlId;
		pki_key *privkey;
		virtual int sigAlg() {
			return NID_undef;
		}
	public:
		pki_x509super(const QString name = "");
		virtual ~pki_x509super();
		virtual int verify()
		{
			return -1;
		};
		unsigned pubHash();
		virtual pki_key *getPubKey() const
		{
			return NULL;
		};
		virtual extList getV3ext()
		{
			return extList();
		};
		virtual QString getSigAlg();
		virtual const EVP_MD *getDigest();
		QVariant getKeySqlId()
		{
			return keySqlId;
		}
		pki_key *getRefKey() const;
		bool compareRefKey(pki_key* ref) const;
		void setRefKey(pki_key *ref);
		void delRefKey(pki_key *ref);
		QVariant column_data(dbheader *hd);
		void opensslConf(QString fname);
		bool visible();
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		QSqlError restoreSql(QVariant sqlId);
};

#endif
