/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
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

class pki_x509name : public pki_base
{
    public:
	pki_x509name(const QString name = "");
	virtual x509name getSubject() const
	{
		return x509name();
	};
	void autoIntName();
	QVariant column_data(dbheader *hd);
	bool visible();
};

class pki_x509super : public pki_x509name
{
		Q_OBJECT
	protected:
		pki_key *privkey;
		virtual const ASN1_OBJECT *sigAlg() {
			return NULL;
		}
	public:
		pki_x509super(const QString name = "");
		virtual ~pki_x509super();
		virtual int verify()
		{
			return -1;
		};
		virtual pki_key *getPubKey() const
		{
			return NULL;
		};
		virtual extList getV3ext()
		{
			return extList();
		};
		virtual QString getSigAlg();
		virtual const EVP_MD *getDigest();
		virtual bool isSpki() const
		{
			return false;
		}
		pki_key *getRefKey() const;
		void setRefKey(pki_key *ref);
		void delRefKey(pki_key *ref);
		QVariant column_data(dbheader *hd);
		void opensslConf(QString fname);
		bool visible();
};

#endif
