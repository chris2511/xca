/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_PKCS12_H
#define __PKI_PKCS12_H

#include <iostream>
#include <openssl/pem.h>
#include <openssl/stack.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include "pki_evp.h"
#include "pki_x509.h"

class pki_pkcs12: public pki_base
{
		Q_OBJECT
	friend class pki_x509;
	    friend class pki_evp;

	protected:
		QString alias;
		pki_x509 *cert;
		pki_evp *key;
		STACK_OF(X509) *certstack;
	public:

		pki_pkcs12(const QString d, pki_x509 *acert, pki_evp *akey);
		pki_pkcs12(const QString fname);

		~pki_pkcs12();
		void addCaCert(pki_x509 *acert);
		pki_key *getKey();
		pki_x509 *getCert();
		pki_x509 *getCa(int x);
		int numCa(); // number of ca certs;
		void writePKCS12(const QString fname);
};

#endif
