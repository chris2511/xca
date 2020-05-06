/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_X509_H
#define __PKI_X509_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "database_model.h"
#include "pki_x509super.h"
#include "x509rev.h"
#include "x509v3ext.h"
#include "pkcs11.h"

#define VIEW_x509_serial 7
#define VIEW_x509_issuer 8
#define VIEW_x509_ca 9
#define VIEW_x509_cert 10
#define VIEW_x509_auth_template 11
#define VIEW_x509_auth_crlExpire 12
#define VIEW_x509_auth_crlNo 13
#define VIEW_x509_auth_crlDays 14
#define VIEW_x509_auth_dnPolicy_UNUSED 15
#define VIEW_x509_revocation 16

class pki_key;

class pki_x509 : public pki_x509super
{
		Q_OBJECT
	private:
		QVariant issuerSqlId;
		a1time crlExpire;
		a1int crlNumber;
		int crlDays;
		QVariant caTemplateSqlId;
		X509 *cert;
		void init();
		x509rev revocation;
		x509revList fromDataRevList;
		void resetX509ReqCount() const;

	protected:
		int sigAlg() const;
		void collect_properties(QMap<QString, QString> &prp) const;

	public:
		pki_x509(X509 *c);
		pki_x509(const pki_x509 *crt);
		pki_x509(const QString &name = QString());
		~pki_x509();

		void setSigner(pki_x509 *s)
		{
			issuerSqlId = s ? s->getSqlItemId() : QVariant();
		}
		void fload(const QString &fname);
		void load_token(pkcs11 &p11, CK_OBJECT_HANDLE object);
		void store_token(bool alwaysSelect);
		void fromPEM_BIO(BIO *bio, const QString &name);
		void writeDefault(const QString &dirname) const;
		a1int hashInfo(const EVP_MD *md) const;
		void setSerial(const a1int &serial);
		a1int getSerial() const;
		void setNotBefore(const a1time &a);
		void setNotAfter(const a1time &a);
		a1time getNotBefore() const;
		a1time getNotAfter() const;
		x509name getSubject() const;
		x509name getIssuerName() const;
		void setSubject(const x509name &n);
		void setIssuer(const x509name &n);
		bool caAndPathLen(bool *ca, a1int *pathlen, bool *hasLen) const;

		void fromData(const unsigned char *p, db_header_t *head);
		bool isCA() const;
		bool canSign() const;
		void writeCert(XFile &file, bool PEM) const;
		QString getIndexEntry();
		bool verify(pki_x509 *signer);
		bool verify_only(const pki_x509 *signer) const;
		pki_key *getPubKey() const;
		void setPubKey(pki_key *key);
		pki_x509 *getSigner();
		void delSigner(pki_base *s);
		QString fingerprint(const EVP_MD *digest) const;
		extList getV3ext() const;
		bool checkDate();
		bool addV3ext(const x509v3ext &e, bool skip_existing = false);
		void sign(pki_key *signkey, const EVP_MD *digest);
		pki_x509 *findIssuer();
		X509 *getCert()
		{
			return cert;
		}
		void setRevoked(bool rev, a1time inval = a1time(),
				QString reason = QString());
		void setRevoked(const x509rev &revok);
		bool isRevoked() const;
		pki_x509 *getBySerial(const a1int &a) const;
		a1int getCrlNumber() const
		{
			return crlNumber;
		}
		void setCrlNumber(a1int n)
		{
			if (n > crlNumber)
				crlNumber = n;
		}
		void setTemplateSqlId(QVariant sqlId)
		{
			caTemplateSqlId = sqlId;
		}
		QVariant getTemplateSqlId()
		{
			return caTemplateSqlId;
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
		x509rev getRevocation()
		{
			return revocation;
		}
		pk11_attlist objectAttributes();
		bool hasExtension(int nid) const;
		bool cmpIssuerAndSerial(pki_x509 *refcert);
		bool visible() const;
		void updateView();
		void print(BioByteArray &b, enum print_opt opt) const;
		x509v3ext getExtByNid(int nid) const;
		QVariant column_data(const dbheader *hd) const;
		QVariant getIcon(const dbheader *hd) const;
		a1time column_a1time(const dbheader *hd) const;
		QByteArray i2d() const;
		void d2i(QByteArray &ba);
		void deleteFromToken();
		void deleteFromToken(const slotid &slot);
		QString getMsg(msg_type msg) const;
		int renameOnToken(const slotid &slot, const QString &name);
		bool pem(BioByteArray &, int);
		QVariant bg_color(const dbheader *hd) const;
		void mergeRevList(x509revList &l);
		void setRevocations(const x509revList &rl);
		x509revList getRevList() const;
		bool compareNameAndKey(pki_x509 *other);
		void setCrlExpire(a1time a)
		{
			crlExpire = a;
		}
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
		QStringList icsVEVENT() const;
		QStringList icsVEVENT_ca() const;
};

Q_DECLARE_METATYPE(pki_x509 *);
#endif
