/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_X509_H
#define __PKI_X509_H

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
		Q_OBJECT
	private:
		pki_x509 *psigner;
		a1time revoked, crlExpiry, invalDate;
		bool isrevoked, randomSerial;
		int trust;
		int efftrust;
		a1int caSerial;
		a1int crlNumber;
		int crlDays;
		QString caTemplate;
		X509 *cert;
		QString revoke_reason;
		void init();
	public:
		static QPixmap *icon[6];
		static bool dont_colorize_expiries;
		pki_x509(X509 *c);
		pki_x509(const pki_x509 *crt);
		pki_x509(const QString name = "");
		~pki_x509();

		void fload(const QString fname);
		void load_token(pkcs11 &p11, CK_OBJECT_HANDLE object);
		void store_token(bool alwaysSelect);
		void fromPEM_BIO(BIO *bio, QString name);
		void writeDefault(const QString fname);
		a1int hashInfo(const EVP_MD *md) const;
		a1int getQASerial(const a1int &secret) const;
		bool verifyQASerial(const a1int &secret) const;
		void setSerial(const a1int &serial);
		a1int getSerial() const;
		void setNotBefore(const a1time &a);
		void setNotAfter(const a1time &a);
		a1time getNotBefore() const;
		a1time getNotAfter() const;
		x509name getSubject() const;
		x509name getIssuer() const;
		void setSubject(const x509name &n);
		void setIssuer(const x509name &n);
		bool caAndPathLen(bool *ca, a1int *pathlen, bool *hasLen);

		QByteArray toData();
		void fromData(const unsigned char *p, db_header_t *head);
		void oldFromData(unsigned char *p, int size);
		bool canSign();
		void writeCert(const QString fname, bool PEM, bool append = false);
		bool verify(pki_x509 *signer);
		pki_key *getPubKey() const;
		void setPubKey(pki_key *key);
		pki_x509 *getSigner();
		void delSigner(pki_base *s);
		QString fingerprint(const EVP_MD *digest);
		extList getV3ext();
		bool checkDate();
		void addV3ext(const x509v3ext &e);
		void sign(pki_key *signkey, const EVP_MD *digest);
		X509 *getCert()
		{
			return cert;
		}
		int getTrust();
		void setTrust(int t);
		int getEffTrust();
		void setEffTrust(int t);
		void setRevoked(bool rev, a1time inval = a1time(),
				QString reason = QString());
		void setRevoked(const a1time &when);
		a1time &getRevoked();
		bool isRevoked();
		int calcEffTrust();
		a1int getIncCaSerial();
		a1int getCaSerial()
		{
			return caSerial;
		}
		void setCaSerial(a1int s)
		{
			caSerial = s;
		}
		a1int getIncCrlNumber()
		{
			return ++crlNumber;
		}
		void setTemplate(QString s)
		{
			if (s.length() > 0)
				caTemplate = s;
		}
		QString getTemplate()
		{
			return caTemplate;
		}
		void setCrlDays(int s)
		{
			if (s > 0)
				crlDays = s;
		}
		int getCrlDays()
		{
			return crlDays;
		}
		bool usesRandomSerial()
		{
			return randomSerial;
		}
		void setUseRandomSerial(bool r)
		{
			randomSerial = r;
		}
		pk11_attlist objectAttributes();
		void setCrlExpiry(const a1time &time);
		bool hasExtension(int nid);
		bool cmpIssuerAndSerial(pki_x509 *refcert);
		void updateView();
		x509rev getRev(bool reason = true);
		QString getSigAlg();
		x509v3ext getExtByNid(int nid);
		const EVP_MD *getDigest();
		QVariant column_data(dbheader *hd);
		QVariant getIcon(dbheader *hd);
		QByteArray i2d();
		void d2i(QByteArray &ba);
		void deleteFromToken();
		void deleteFromToken(slotid slot);
		virtual QString getMsg(msg_type msg);
		virtual int renameOnToken(slotid slot, QString name);
		BIO *pem(BIO *);
		virtual QVariant bg_color(dbheader *hd);
};

#endif
