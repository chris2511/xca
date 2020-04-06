/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_X509REQ_H
#define __PKI_X509REQ_H

#include <openssl/x509.h>
#include <openssl/pem.h>
#include "pki_key.h"
#include "pki_x509super.h"
#include "x509v3ext.h"
#include "x509name.h"

#define VIEW_x509req_request 7
#define VIEW_x509req_signed 8

class pki_x509;

class pki_x509req : public pki_x509super
{
		Q_OBJECT

		mutable int x509count;
	protected:
		X509_REQ *request;
		bool done;
		int sigAlg() const;
		void collect_properties(QMap<QString, QString> &prp) const;

	public:
		pki_x509req(const QString &name = QString());
		pki_x509req(const pki_x509req *req);
		~pki_x509req();

		extList getV3ext() const;
		void fromPEM_BIO(BIO *bio, const QString &name);
		void fload(const QString &fname);
		void writeDefault(const QString &dirname) const;
		void fromData(const unsigned char *p, db_header_t *head);
		x509name getSubject() const;
		void writeReq(XFile &file, bool pem) const;
		void markSigned(bool signe);
		void print(BioByteArray &b, enum print_opt opt) const;
		X509_REQ *getReq()
		{
			return request;
		}
		void addAttribute(int nid, QString content);
		QString getAttribute(int nid) const;
		int issuedCerts() const;

		bool verify() const;
		pki_key *getPubKey() const;
		void createReq(pki_key *key, const x509name &dn,
				const EVP_MD *md, extList el);
		void setSubject(const x509name &n);
		QVariant column_data(const dbheader *hd) const;
		QVariant getIcon(const dbheader *hd) const;
		void setDone(bool d = true)
		{
			done = d;
		}
		bool getDone() const
		{
			return done;
		}
		void resetX509count() const
		{
			x509count = -1;
		}
		virtual QString getMsg(msg_type msg) const;
		void d2i(QByteArray &ba);
		QByteArray i2d() const;
		bool pem(BioByteArray &, int);
		bool visible() const;
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
};

Q_DECLARE_METATYPE(pki_x509req *);
#endif
