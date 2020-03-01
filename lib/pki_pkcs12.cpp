/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_pkcs12.h"
#include "pki_evp.h"
#include "pki_x509.h"

#include "pass_info.h"
#include "exception.h"
#include "func.h"
#include "widgets/PwDialog.h"
#include "widgets/XcaWarning.h"
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/stack.h>

#include <QMessageBox>

#include "openssl_compat.h"

pki_pkcs12::pki_pkcs12(const QString &d, pki_x509 *acert, pki_key *akey)
	:pki_multi(d), cert(acert), key(akey)
{
	append_item(key);
	append_item(cert);
}

pki_pkcs12::pki_pkcs12(const QString &fname)
	:pki_multi(fname)
{
	Passwd pass;
	EVP_PKEY *mykey = NULL;
	X509 *mycert = NULL;
	key = NULL; cert = NULL;
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
			failed_files << fname;
			throw result;
		}
	}
	STACK_OF(X509) *certstack = sk_X509_new_null();
	PKCS12_parse(pkcs12, pass.constData(), &mykey, &mycert, &certstack);
	int error = ERR_peek_error();
	if (ERR_GET_REASON(error) == PKCS12_R_MAC_VERIFY_FAILURE) {
		pki_ign_openssl_error();
		PKCS12_free(pkcs12);
		sk_X509_free(certstack);
		failed_files << fname;

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
		check_oom(cert);
		if (alias.isEmpty()) {
			cert->autoIntName(fname);
			alias = cert->getIntName();
		} else {
			cert->setIntName(alias);
		}
		cert->pkiSource = imported;
		inheritFilename(cert);
		append_item(cert);
	}
	if (mykey) {
		key = new pki_evp(mykey);
		check_oom(key);
		key->setIntName(alias + "_key");
		key->pkiSource = imported;
		inheritFilename(key);
		append_item(key);
	}
	for (int i = 0; i < sk_X509_num(certstack); ++i) {
		X509 *crt = sk_X509_value(certstack, i);
		if (!crt)
			continue;
		pki_x509 *cacert = new pki_x509(crt);
		check_oom(cacert);
		if (alias.isEmpty()) {
			cacert->autoIntName(QString());
		} else {
			cacert->setIntName(QString(alias + "_ca_%1").arg(i));
		}
		cacert->pkiSource = imported;
		inheritFilename(cacert);
		append_item(cacert);
	}
	sk_X509_free(certstack);
	PKCS12_free(pkcs12);
	pki_openssl_error();
}

void pki_pkcs12::writePKCS12(XFile &file) const
{
	Passwd pass;
	PKCS12 *pkcs12;
	pass_info p(XCA_TITLE,
		tr("Please enter the password to encrypt the PKCS#12 file"));

	if (cert == NULL || key == NULL)
		my_error(tr("No key or no Cert and no pkcs12"));

	if (PwDialog::execute(&p, &pass, true) != 1)
		return;

	STACK_OF(X509) *certstack = sk_X509_new_null();
	foreach(pki_base *pki, multi) {
		pki_x509 *x = dynamic_cast<pki_x509*>(pki);
		if (x && x != cert)
			sk_X509_push(certstack, x->getCert());
	}
	pkcs12 = PKCS12_create(pass.data(), getIntName().toUtf8().data(),
				key->decryptKey(), cert->getCert(), certstack,
				0, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
				0, 0, 0);
	i2d_PKCS12_fp(file.fp(), pkcs12);
	sk_X509_free(certstack);
	pki_openssl_error();
	PKCS12_free(pkcs12);
}
