/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_PKCS7_H
#define __PKI_PKCS7_H

#include "pki_x509.h"

class pki_pkcs7: public pki_base
{
		Q_OBJECT
	friend class pki_x509;
	protected:
		PKCS7 *p7;
		STACK_OF(X509) *getCertStack();
		void signBio(pki_x509 *crt, BIO * bio);
		void encryptBio(pki_x509 *crt, BIO * bio);
	public:
		pki_pkcs7(const QString name = "");
		/* destructor */
		virtual ~pki_pkcs7();

		void signFile(pki_x509 *crt, QString filename);
		void signCert(pki_x509 *crt, pki_x509 *contCert);
		void encryptFile(pki_x509 *crt, QString filename);
		void writeP7(QString fname,bool PEM);
		void fromPEM_BIO(BIO *bio, QString name);
		void fload(const QString fname);
		pki_x509 *getCert(int x);
		void addCert(pki_x509 *crt);
		int numCert(); // number of certs;

};

#endif
