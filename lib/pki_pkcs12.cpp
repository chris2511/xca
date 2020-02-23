/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_pkcs12.h"
#include "pass_info.h"
#include "exception.h"
#include "func.h"
#include "widgets/PwDialog.h"
#include "widgets/XcaWarning.h"
#include <openssl/err.h>
#include <QMessageBox>

#include "openssl_compat.h"

pki_pkcs12::pki_pkcs12(const QString &d, pki_x509 *acert, pki_evp *akey)
	:pki_base(d)
{
	key = new pki_evp(akey);
	cert = new pki_x509(acert);
	certstack = sk_X509_new_null();
	pki_openssl_error();
}

pki_pkcs12::pki_pkcs12(const QString &fname)
	:pki_base(fname)
{
	Passwd pass;
	EVP_PKEY *mykey = NULL;
	X509 *mycert = NULL;

	key=NULL; cert=NULL;
	certstack = sk_X509_new_null();
	pass_info p(XCA_TITLE, tr("Please enter the password to decrypt the PKCS#12 file:\n%1").arg(compressFilename(fname)));

	setFilename(fname);
	XFile file(fname);
	file.open_read();
	PKCS12 *pkcs12 = d2i_PKCS12_fp(file.fp(), NULL);
	if (pki_ign_openssl_error()) {
		if (pkcs12)
			PKCS12_free(pkcs12);
		throw errorEx(tr("Unable to load the PKCS#12 (pfx) file %1.")
				.arg(fname));
	}
	while (!PKCS12_verify_mac(pkcs12, pass.constData(), pass.size())) {
		if (pass.size() > 0)
			XCA_PASSWD_ERROR();
		enum open_result result = PwDialog::execute(&p, &pass);
		if (result != pw_ok) {
			/* cancel pressed */
			PKCS12_free(pkcs12);
			throw result;
		}
	}
	PKCS12_parse(pkcs12, pass.constData(), &mykey, &mycert, &certstack);
	int error = ERR_peek_error();
	if (ERR_GET_REASON(error) == PKCS12_R_MAC_VERIFY_FAILURE) {
		pki_ign_openssl_error();
		PKCS12_free(pkcs12);
		throw errorEx(getClassName(),
			 tr("The supplied password was wrong (%1)")
				.arg(ERR_reason_error_string(error)));
	}
	pki_ign_openssl_error();
	if (mycert) {
		unsigned char *str = X509_alias_get0(mycert, NULL);
		if (str)
			alias = QString::fromUtf8((const char *)str);
		alias = QString::fromUtf8(alias.toLatin1());
		cert = new pki_x509(mycert);
		if (alias.isEmpty()) {
			cert->autoIntName(fname);
		} else {
			cert->setIntName(alias);
		}
		alias = cert->getIntName();
		cert->pkiSource = imported;
		inheritFilename(cert);
	}
	if (mykey) {
		key = new pki_evp(mykey);
		key->setIntName(alias + "_key");
		key->pkiSource = imported;
		inheritFilename(key);
	}
	PKCS12_free(pkcs12);
}

pki_pkcs12::~pki_pkcs12()
{
	if (sk_X509_num(certstack) > 0) {
		// free the certs itself, because we own a copy of them
		sk_X509_pop_free(certstack, X509_free);
	}
	delete key;
	delete cert;
	pki_openssl_error();
}


void pki_pkcs12::addCaCert(pki_x509 *ca)
{
	if (!ca)
		return;
	sk_X509_push(certstack, X509_dup(ca->getCert()));
	pki_openssl_error();
}

void pki_pkcs12::writePKCS12(XFile &file) const
{
	Passwd pass;
	pass_info p(XCA_TITLE,
		tr("Please enter the password to encrypt the PKCS#12 file"));
	PKCS12 *pkcs12;

	if (cert == NULL || key == NULL)
		my_error(tr("No key or no Cert and no pkcs12"));

	if (PwDialog::execute(&p, &pass, true) != 1)
		return;

	pkcs12 = PKCS12_create(pass.data(), getIntName().toUtf8().data(),
				key->decryptKey(), cert->getCert(), certstack,
				0, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
				0, 0, 0);
	i2d_PKCS12_fp(file.fp(), pkcs12);
	pki_openssl_error();
	PKCS12_free(pkcs12);
}

int pki_pkcs12::numCa() const
{
	int n = sk_X509_num(certstack);
	pki_openssl_error();
	return n;
}

pki_key *pki_pkcs12::getKey() const
{
	return key ? new pki_evp(key) : NULL;
}

pki_x509 *pki_pkcs12::getCert() const
{
	return cert ? new pki_x509(cert) : NULL;
}

pki_x509 *pki_pkcs12::getCa(int x) const
{
	pki_x509 *cert = NULL;
	X509 *crt = X509_dup(sk_X509_value(certstack, x));
	if (crt) {
		cert = new pki_x509(crt);
		if (alias.isEmpty()) {
			cert->autoIntName(QString());
		} else {
			cert->setIntName(QString(alias + "_ca_%1").arg(x));
		}
		cert->pkiSource = imported;
		cert->setFilename(getFilename());
		inheritFilename(cert);
	}
	pki_openssl_error();
	return cert;
}

void pki_pkcs12::print(FILE *fp) const
{
	QList<pki_base *> items;

	for (int i=0; i < numCa(); i++)
		items << getCa(i);

	items << getCert() << getKey();

	foreach(pki_base *pki, items)
		pki->print(fp);

	qDeleteAll(items);
}
