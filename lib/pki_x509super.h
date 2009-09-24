/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef PKI_X509SUPER_H
#define PKI_X509SUPER_H

#include <openssl/x509.h>
#include <openssl/pem.h>
#include "pki_key.h"
#include "x509name.h"
#include "x509v3ext.h"

//class pki_x509;

class pki_x509super : public pki_base
{
	protected:
		pki_key *privkey;
	public:
		pki_x509super(const QString name = "");
		virtual ~pki_x509super();
		virtual x509name getSubject() const { return x509name(); };
		virtual int verify() { return -1; };
		virtual pki_key *getPubKey() const { return NULL; };
		virtual extList getV3ext() { return extList(); };

		pki_key *getRefKey() const;
		void setRefKey(pki_key *ref);
		void delRefKey(pki_key *ref);
		void autoIntName();
};

#endif
