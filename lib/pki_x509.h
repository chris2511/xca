/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef PKI_X509_H
#define PKI_X509_H

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "pki_key.h"
#include "pki_x509req.h"
#include "pki_x509super.h"
#include "asn1time.h"
#include "asn1int.h"
#include "x509rev.h"
#include "x509v3ext.h"
#include "pkcs11.h"

class pki_x509 : public pki_x509super
{
	private:
		pki_x509 *psigner;
		a1time revoked, crlExpiry;
		bool isrevoked;
		int trust;
		int efftrust;
		a1int caSerial;
		int crlDays;
		QString caTemplate;
		X509 *cert;
		void init();
		void set_date(ASN1_TIME **a, const a1time &a1);
	public:
		static QPixmap *icon[5];
		pki_x509(X509 *c);
		pki_x509(const pki_x509 *crt);
		pki_x509(const QString name = "");
		~pki_x509();

		void fload(const QString fname);
		void load_token(pkcs11 &p11, CK_OBJECT_HANDLE object);
		void store_token();
		void fromPEM_BIO(BIO *bio, QString name);
		void writeDefault(const QString fname);
		a1int hashInfo(const EVP_MD *md) const;
		a1int getQASerial(const a1int &secret) const;
		bool verifyQASerial(const a1int &secret) const;
		void setSerial(const a1int &serial);
		a1int getSerial() const;
		void setNotBefore(const a1time &a1);
		void setNotAfter(const a1time &a1);
		a1time getNotBefore() const;
		a1time getNotAfter() const;
		x509name getSubject() const;
		x509name getIssuer() const;
		void setSubject(const x509name &n);
		void setIssuer(const x509name &n);

		unsigned char *toData(int *size);
		void fromData(const unsigned char *p, db_header_t *head);
		void oldFromData(unsigned char *p, int size);
		bool compare(pki_base *refcert);
		bool canSign();
		void writeCert(const QString fname, bool PEM, bool append = false);
		bool verify(pki_x509 *signer);
		pki_key *getPubKey() const;
		void setPubKey(pki_key *key);
		pki_x509 *getSigner();
		void delSigner(pki_base *s);
		QString fingerprint(const EVP_MD *digest);
		extList getV3ext();
		int checkDate();
		void addV3ext(const x509v3ext &e);
		void sign(pki_key *signkey, const EVP_MD *digest);
		X509 *getCert(){ return cert;}
		int getTrust();
		void setTrust(int t);
		int getEffTrust();
		void setEffTrust(int t);
		void setRevoked(bool rev);
		void setRevoked(const a1time &when);
		a1time &getRevoked();
		bool isRevoked();
		int calcEffTrust();
		a1int getIncCaSerial();
		a1int getCaSerial();
		void setCaSerial(a1int s);
		void setTemplate(QString s);
		QString getTemplate();
		void setCrlDays(int s);
		int getCrlDays();
		void setCrlExpiry(const a1time &time);
		int resetTimes(pki_x509 *signer);
		bool hasExtension(int nid);
		bool cmpIssuerAndSerial(pki_x509 *refcert);
		void updateView();
		x509rev getRev();
		QString getSigAlg();
		x509v3ext getExtByNid(int nid);
		const EVP_MD *getDigest();
		QVariant column_data(int col);
		QVariant getIcon(int column);
		QByteArray i2d();
		void deleteFromToken();
};

#endif
