/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_X509REQ_H
#define __PKI_X509REQ_H

#include <openssl/x509.h>
#include <openssl/pem.h>
#include "pki_key.h"
#include "x509v3ext.h"
#include "pki_x509super.h"
#include "x509name.h"

#define VIEW_x509req_request 7
#define VIEW_x509req_signed 8

class pki_x509;

class pki_x509req : public pki_x509super
{
		Q_OBJECT

	protected:
		X509_REQ *request;
		bool done;
		int sigAlg();

	public:
		extList getV3ext();
		static QPixmap *icon[3];
		const char *getClassName() const;
		pki_x509req(QString name = "");
		void fromPEM_BIO(BIO *bio, QString name);
		void fload(const QString fname);
		void writeDefault(const QString fname);
		~pki_x509req();
		void fromData(const unsigned char *p, db_header_t *head);
		x509name getSubject() const;
		void writeReq(const QString fname, bool pem);
		X509_REQ *getReq()
		{
			return request;
		}
		void addAttribute(int nid, QString content);
		QString getAttribute(int nid);

		int verify();
		pki_key *getPubKey() const;
		void createReq(pki_key *key, const x509name &dn,
			const EVP_MD *md, extList el);
		void setSubject(const x509name &n);
		/* SPKAC special functions */
		QVariant column_data(dbheader *hd);
		QVariant getIcon(dbheader *hd);
		void setDone(bool d = true)
		{
			done = d;
		}
		bool getDone()
		{
			return done;
		}
		virtual QString getMsg(msg_type msg);
		void d2i(QByteArray &ba);
		QByteArray i2d();
		BIO *pem(BIO *, int);
		bool visible();
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(QSqlRecord &rec);
};

Q_DECLARE_METATYPE(pki_x509req *);
#endif
