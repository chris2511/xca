/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __PKI_CRL_H
#define __PKI_CRL_H

#include <openssl/bio.h>
#include "pki_x509.h"
#include "x509name.h"

#define VIEW_crls_num 6
#define VIEW_crls_issuer 7
#define VIEW_crls_crl 8

#include "widgets/hashBox.h"
class crljob
{
    public:
	pki_x509 *issuer;
	bool withReason;
	bool authKeyId;
	bool subAltName;
	bool setCrlNumber;
	a1int crlNumber;
	int crlDays;
	const EVP_MD *hashAlgo;
	a1time lastUpdate;
	a1time nextUpdate;

	crljob(pki_x509 *x) : issuer(x)
	{
		withReason = true;
		authKeyId = true;
		subAltName = true;
		setCrlNumber = issuer->getCrlNumber().getLong() > 0;
		crlNumber = issuer->getCrlNumber();
		crlNumber++;
		crlDays = issuer->getCrlDays();
		hashAlgo = hashBox::getDefaultMD();
		nextUpdate = lastUpdate.addDays(crlDays);
	}
};

class pki_crl: public pki_x509name
{
		Q_OBJECT
	friend class pki_x509;
	protected:
		QVariant issuerSqlId;
		X509_CRL *crl;
		extList extensions() const;
		void collect_properties(QMap<QString, QString> &prp) const;
	public:
		pki_crl(const QString name = "");
		~pki_crl();
		void fromPEM_BIO(BIO *bio, const QString &name);
		void fload(const QString &fname);
		QString getSigAlg() const;
		void writeDefault(const QString &dirname) const;
		void createCrl(const QString d, pki_x509 *iss);
		void addRev(const x509rev &rev, bool withReason=true);
		void addExt(int nid, QString value);
		void addV3ext(const x509v3ext &e);
		void sign(pki_key *key, const EVP_MD *md = EVP_md5());
		void writeCrl(XFile &file, bool pem = true) const;
		pki_x509 *getIssuer() const;
		QString getIssuerName() const;
		void setIssuer(pki_x509 *iss);
		x509name getSubject() const;
		void setLastUpdate(const a1time &t);
		void setNextUpdate(const a1time &t);
		a1time getNextUpdate() const;
		a1time getLastUpdate() const;
		void fromData(const unsigned char *p, db_header_t *head);
		bool verify(pki_x509 *issuer);
		int numRev() const;
		x509revList getRevList();
		QString printV3ext();
		x509v3ext getExtByNid(int nid);
		a1int getVersion();
		QVariant column_data(const dbheader *hd) const;
		QVariant getIcon(const dbheader *hd) const;
		a1time column_a1time(const dbheader *hd) const;
		QString getMsg(msg_type msg) const;
		void d2i(QByteArray &ba);
		QByteArray i2d() const;
		void setCrlNumber(a1int num);
		bool getCrlNumber(a1int *num) const;
		a1int getCrlNumber() const;
		bool pem(BioByteArray &, int);
		bool visible() const;
		QSqlError lookupIssuer();
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
		QStringList icsVEVENT() const;
		void print(BioByteArray &b, enum print_opt opt) const;
};

#endif
