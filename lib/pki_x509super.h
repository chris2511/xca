/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
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

#define VIEW_x509super_keyid 6

class pki_x509name : public pki_base
{
    protected:
	void PEM_file_comment(XFile &file) const;

    public:
	pki_x509name(const QString &name = QString());
	pki_x509name(const pki_x509name *n);
	virtual x509name getSubject() const = 0;
	void autoIntName(const QString &file);
	QVariant column_data(const dbheader *hd) const;
	bool visible() const;
	void collect_properties(QMap<QString, QString> &prp) const;
};

class pki_x509super : public pki_x509name
{
		Q_OBJECT
	protected:
		QVariant keySqlId;
		virtual int sigAlg() const = 0;
		void collect_properties(QMap<QString, QString> &prp) const;
	public:
		pki_x509super(const QString &name = QString());
		pki_x509super(const pki_x509super *x);
		virtual ~pki_x509super();
		unsigned pubHash() const;
		virtual pki_key *getPubKey() const = 0;
		virtual extList getV3ext() const = 0;
		virtual QString getSigAlg() const;
		virtual const EVP_MD *getDigest();
		QVariant getKeySqlId()
		{
			return keySqlId;
		}
		pki_key *getRefKey() const;
		bool compareRefKey(pki_key* ref) const;
		void setRefKey(pki_key *ref);
		void delRefKey(pki_key *ref);
		QVariant column_data(const dbheader *hd) const;
		void opensslConf(QString fname);
		bool visible() const;
		bool hasPrivKey() const;
		QVariant getIcon(const dbheader *hd) const;
		QSqlError lookupKey();
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
};

#endif
