/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_PKCS7_H
#define __PKI_PKCS7_H

#include <QString>
#include "pki_multi.h"

#include <openssl/pkcs7.h>

class pki_x509;

class pki_pkcs7: public pki_multi
{
		Q_OBJECT

	friend class pki_x509;

	protected:
		PKCS7 *p7;
		void signBio(pki_x509 *crt, BIO *bio);
		void encryptBio(pki_x509 *crt, BIO *bio);
		void append_certs(PKCS7 *myp7, const QString &name);

	public:
		pki_pkcs7(const QString &name = QString());
		virtual ~pki_pkcs7();

		void signFile(pki_x509 *crt, const QString &filename);
		void signCert(pki_x509 *crt, pki_x509 *contCert);
		void encryptFile(pki_x509 *crt, const QString &filename);
		void writeP7(XFile &file, bool PEM);
		void fromPEM_BIO(BIO *bio, const QString &name);
		void fload(const QString &name);
};
#endif
