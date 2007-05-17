/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef PKI_CRL_H
#define PKI_CRL_H

#include <iostream>
#include <openssl/pem.h>
#include "pki_x509.h"
#include "x509name.h"
#include "asn1time.h"
#include "asn1int.h"

class pki_crl: public pki_base
{
    friend class pki_x509;
	protected:
		pki_x509 *issuer;
		X509_CRL *crl;
	public:
		pki_crl(const QString name = "");
		/* destructor */
		~pki_crl();
		void fload(const QString fname);
		QString getSigAlg();
		void writeDefault(const QString fname);
		static QPixmap *icon;
		void createCrl(const QString d, pki_x509 *iss);
		void addRev(const x509rev &rev);
		void addExt(int nid, QString value);
		void write(QString fname);
		void addV3ext(const x509v3ext &e);
		void sign(pki_key *key, const EVP_MD *md = EVP_md5());
		void writeCrl(const QString fname, bool pem = true);
		pki_x509 *getIssuer();
		void setIssuer(pki_x509 *iss);
		x509name getIssuerName();
		void setLastUpdate(const a1time &t);
		void setNextUpdate(const a1time &t);
		a1time getNextUpdate();
		a1time getLastUpdate();
		void fromData(const unsigned char *p, db_header_t *head);
		void oldFromData(unsigned char *p, int size);
		unsigned char *toData(int *size);
		bool compare(pki_base *refcrl);
		int numRev();
		bool verify(pki_key *pkey);
		x509rev getRev(int num);
		QString printV3ext();
		x509v3ext getExtByNid(int nid);
		a1int getVersion();
		QVariant column_data(int col);
		QVariant getIcon();
};

#endif
