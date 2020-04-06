/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_pkcs7.h"
#include "pki_x509.h"
#include "pki_key.h"
#include "func.h"
#include "exception.h"

#include <openssl/x509.h>

pki_pkcs7::pki_pkcs7(const QString &name)
	:pki_multi(name)
{
	p7 = NULL;
}

pki_pkcs7::~pki_pkcs7()
{
	if (p7)
		PKCS7_free(p7);
}

void pki_pkcs7::encryptFile(pki_x509 *crt, const QString &filename)
{
	encryptBio(crt, XFile(filename).bio());
}

void pki_pkcs7::encryptBio(pki_x509 *crt, BIO *bio)
{
	STACK_OF(X509) *certstack;
	if (!crt)
		return;
	certstack = sk_X509_new_null();
	sk_X509_push(certstack, crt->getCert());
	openssl_error();
	if (p7)
		PKCS7_free(p7);
	p7 = PKCS7_encrypt(certstack, bio, EVP_des_ede3_cbc(), PKCS7_BINARY);
	openssl_error();
	sk_X509_free(certstack);
}

void pki_pkcs7::signBio(pki_x509 *crt, BIO *bio)
{
	pki_key *privkey;
	EVP_PKEY *pk;
	STACK_OF(X509) *certstack;
	if (!crt)
		return;
	privkey = crt->getRefKey();
	if (!privkey)
		throw errorEx("No private key for signing found", getClassName());
	certstack = sk_X509_new_null();

	pki_x509 *signer = crt->getSigner();
	if (signer == crt)
		signer = NULL;
	while (signer != NULL ) {
		sk_X509_push(certstack, signer->getCert());
	        openssl_error();
		if (signer == signer->getSigner() )
			signer = NULL;
		else
			signer = signer->getSigner();
	}
	if (p7)
		PKCS7_free(p7);
	pk = privkey->decryptKey();
	p7 = PKCS7_sign(crt->getCert(), pk, certstack, bio, PKCS7_BINARY);
	EVP_PKEY_free(pk);
	openssl_error();
	sk_X509_free(certstack);
}

void pki_pkcs7::signFile(pki_x509 *crt, const QString &filename)
{
	if (crt)
		signBio(crt, XFile(filename).bio());
}

void pki_pkcs7::signCert(pki_x509 *crt, pki_x509 *contCert)
{
	BioByteArray bba;
	i2d_X509_bio(bba, contCert->getCert());
	signBio(crt, bba);
        openssl_error();
}

void pki_pkcs7::writeP7(XFile &file, bool PEM)
{
	if (!p7) {
		p7 = PKCS7_new();
		PKCS7_set_type(p7, NID_pkcs7_signed);
		PKCS7_content_new(p7, NID_pkcs7_data);
		pki_openssl_error();
	}
	foreach(pki_base *pki, multi) {
		pki_x509 *x = dynamic_cast<pki_x509*>(pki);
		if (x)
			PKCS7_add_certificate(p7, X509_dup(x->getCert()));
	}
	if (PEM)
		PEM_write_PKCS7(file.fp(), p7);
	else
		i2d_PKCS7_fp(file.fp(), p7);
	openssl_error();
}

void pki_pkcs7::append_certs(PKCS7 *myp7, const QString &name)
{
	STACK_OF(X509) *certstack = NULL;

	pki_openssl_error();

        if (myp7 == NULL)
		return;

	setFilename(name);
	autoIntName(name);

	switch (OBJ_obj2nid(myp7->type)) {
		case NID_pkcs7_signed:
			certstack = myp7->d.sign->cert;
			myp7->d.sign->cert = NULL;
			break;
		case NID_pkcs7_signedAndEnveloped:
			certstack = myp7->d.signed_and_enveloped->cert;
			myp7->d.signed_and_enveloped->cert = NULL;
			break;
	}
	if (!certstack)
		return;

	for (int x = 0; x < sk_X509_num(certstack); x++) {
		X509 *c = X509_dup(sk_X509_value(certstack, x));
		pki_x509 *cert = new pki_x509(c);
		openssl_error();
		cert->autoIntName(getIntName());
		cert->pkiSource = imported;
		inheritFilename(cert);
		append_item(cert);
	}
	sk_X509_free(certstack);
	PKCS7_free(myp7);
}

void pki_pkcs7::fromPEM_BIO(BIO *bio, const QString &name)
{
	PKCS7 *myp7 = PEM_read_bio_PKCS7(bio, NULL, NULL, NULL);
	append_certs(myp7, name);
}

void pki_pkcs7::fload(const QString &name)
{
	PKCS7 *myp7;
	XFile file(name);
	file.open_read();
	myp7 = PEM_read_PKCS7(file.fp(), NULL, NULL, NULL);
	if (!myp7) {
		ign_openssl_error();
		file.retry_read();
		myp7 = d2i_PKCS7_fp(file.fp(), NULL);
	}
	if (ign_openssl_error()) {
		if (myp7)
			PKCS7_free(myp7);
		throw errorEx(tr("Unable to load the PKCS#7 file %1. Tried PEM and DER format.").arg(name));
	}
	append_certs(myp7, name);
}
