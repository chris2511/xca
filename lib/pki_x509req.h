/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef PKI_X509REQ_H
#define PKI_X509REQ_H

#include <openssl/x509.h>
#include <openssl/pem.h>
#include "pki_key.h"
#include "x509v3ext.h"
#include "pki_x509super.h"
#include "x509name.h"


class pki_x509;

class pki_x509req : public pki_x509super
{
	private:
		//loading spkac file and convert it to a request
		int load_spkac(const QString filename);
		//for checking spkac content-fields
		int fix_data(int nid, int *type);

	protected:
		X509_REQ *request;
		NETSCAPE_SPKI *spki;
		bool done;

	public:
		extList getV3ext();
		static QPixmap *icon[4];
		pki_x509req(QString name = "");
		void fromPEM_BIO(BIO *bio, QString name);
		void fload(const QString fname);
		void writeDefault(const QString fname);
		~pki_x509req();
		void fromData(const unsigned char *p, db_header_t *head);
		void oldFromData(unsigned char *p, int size);
		unsigned char *toData(int *size);
		bool compare(pki_base *refreq);
		x509name getSubject() const;
		bool isSpki() const;
		void writeReq(const QString fname, bool pem);
		X509_REQ *getReq() {return request;}
		void addAttribute(int nid, QString content);

		int verify();
		pki_key *getPubKey() const;
		void createReq(pki_key *key, const x509name &dn, const EVP_MD *md,
		   extList el);
		QString getSigAlg();
		void setSubject(const x509name &n);
		/* SPKAC special functions */
		ASN1_IA5STRING *spki_challange();
		QVariant column_data(int col);
		QVariant getIcon(int column);
		void setDone() { done = true; }
		bool getDone() { return done; }
};

#endif
