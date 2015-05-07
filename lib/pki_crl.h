/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __PKI_CRL_H
#define __PKI_CRL_H

#include <iostream>
#include <openssl/pem.h>
#include "pki_x509.h"
#include "x509name.h"
#include "asn1time.h"
#include "asn1int.h"

class pki_crl: public pki_x509name
{
		Q_OBJECT
	friend class pki_x509;
	protected:
		pki_x509 *issuer;
		X509_CRL *crl;
	public:
		pki_crl(const QString name = "");
		/* destructor */
		~pki_crl();
		void fromPEM_BIO(BIO *bio, QString name);
		void fload(const QString fname);
		QString getSigAlg();
		void writeDefault(const QString fname);
		static QPixmap *icon;
		void createCrl(const QString d, pki_x509 *iss);
		void addRev(const x509rev &rev, bool withReason=true);
		void addExt(int nid, QString value);
		void write(QString fname);
		void addV3ext(const x509v3ext &e);
		void sign(pki_key *key, const EVP_MD *md = EVP_md5());
		void writeCrl(const QString fname, bool pem = true);
		pki_x509 *getIssuer()
		{
			return issuer;
		}
		void setIssuer(pki_x509 *iss)
		{
			 issuer = iss;
		}
		x509name getSubject() const;
		void setLastUpdate(const a1time &t);
		void setNextUpdate(const a1time &t);
		a1time getNextUpdate();
		a1time getLastUpdate();
		void fromData(const unsigned char *p, db_header_t *head);
		void oldFromData(unsigned char *p, int size);
		QByteArray toData();
		bool verify(pki_key *pkey);
		int numRev();
		x509revList getRevList();
		QString printV3ext();
		x509v3ext getExtByNid(int nid);
		a1int getVersion();
		QVariant column_data(dbheader *hd);
		QVariant getIcon(dbheader *hd);
		virtual QString getMsg(msg_type msg);
		void d2i(QByteArray &ba);
		QByteArray i2d();
		void setCrlNumber(a1int num);
		bool getCrlNumber(a1int *num);
		a1int getCrlNumber();
		BIO *pem(BIO *, int);
		bool visible();
};

#endif
