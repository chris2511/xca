/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_pkcs7.h"
#include "func.h"
#include "exception.h"


pki_pkcs7::pki_pkcs7(const QString name)
	:pki_base(name)
{
	p7 = PKCS7_new();
	PKCS7_set_type(p7, NID_pkcs7_signed);
	PKCS7_content_new(p7, NID_pkcs7_data);
	class_name = "pki_pkcs7";
}


pki_pkcs7::~pki_pkcs7()
{
	if (p7)
		PKCS7_free(p7);
}

void pki_pkcs7::encryptFile(pki_x509 *crt, QString filename)
{
	BIO *bio = NULL;
	bio = BIO_new_file(QString2filename(filename), "r");
        openssl_error();
	encryptBio(crt, bio);
	BIO_free(bio);
}

void pki_pkcs7::encryptBio(pki_x509 *crt, BIO *bio)
{
	STACK_OF(X509) *certstack;
	if (!crt) return;
	certstack = sk_X509_new_null();
	sk_X509_push(certstack, crt->getCert());
	openssl_error();
	if (p7) PKCS7_free(p7);
	p7 = PKCS7_encrypt(certstack, bio, EVP_des_ede3_cbc(), PKCS7_BINARY);
	openssl_error();
	sk_X509_free(certstack);
}

void pki_pkcs7::signBio(pki_x509 *crt, BIO *bio)
{
	pki_key *privkey;
	EVP_PKEY *pk;
	STACK_OF(X509) *certstack;
	if (!crt) return;
	privkey = crt->getRefKey();
	if (!privkey) throw errorEx("No private key for signing found", class_name);
	certstack = sk_X509_new_null();

	pki_x509 *signer = crt->getSigner();
	if (signer == crt) signer = NULL;
	while (signer != NULL ) {
		sk_X509_push(certstack, signer->getCert());
	        openssl_error();
		if (signer == signer->getSigner() ) signer = NULL;
		else signer = signer->getSigner();
	}
	if (p7) PKCS7_free(p7);
	pk = privkey->decryptKey();
	p7 = PKCS7_sign(crt->getCert(), pk, certstack, bio, PKCS7_BINARY);
	EVP_PKEY_free(pk);
	openssl_error();
	sk_X509_free(certstack);
}


void pki_pkcs7::signFile(pki_x509 *crt, QString filename)
{
	BIO *bio = NULL;
	if (!crt) return;
	bio = BIO_new_file(QString2filename(filename), "r");
        openssl_error();
	signBio(crt, bio);
	BIO_free(bio);
}

void pki_pkcs7::signCert(pki_x509 *crt, pki_x509 *contCert)
{
	BIO *bio = NULL;
	if (!crt) return;
	bio = BIO_new(BIO_s_mem());
        openssl_error();
	i2d_X509_bio(bio, contCert->getCert());
	signBio(crt, bio);
	BIO_free(bio);
}

void pki_pkcs7::writeP7(QString fname,bool PEM)
{
	FILE *fp;
	fp = fopen_write(fname);
	if (fp != NULL) {
		if (p7){
			if (PEM)
				PEM_write_PKCS7(fp, p7);
			else
				i2d_PKCS7_fp(fp, p7);
			openssl_error();
			fclose(fp);
		}
	}
	else fopen_error(fname);
}

pki_x509 *pki_pkcs7::getCert(int x)
{
	pki_x509 *cert;
	cert = new pki_x509(X509_dup(sk_X509_value(getCertStack(), x)));
	openssl_error();
	cert->autoIntName();
	return cert;
}

int pki_pkcs7::numCert()
{
	int n= sk_X509_num(getCertStack());
	openssl_error();
	return n;
}


void pki_pkcs7::fromPEM_BIO(BIO *bio, QString name)
{
	PKCS7 *_p7;
	_p7 = PEM_read_bio_PKCS7(bio, NULL, NULL, NULL);
	openssl_error(name);
	PKCS7_free(p7);
	p7 = _p7;
	setIntName(rmslashdot(name));
}

void pki_pkcs7::fload(const QString fname)
{
	FILE *fp;
	PKCS7 *_p7;
	fp = fopen_read(fname);
	if (fp) {
		_p7 = PEM_read_PKCS7(fp, NULL, NULL, NULL);
		if (!_p7) {
			ign_openssl_error();
			rewind(fp);
			_p7 = d2i_PKCS7_fp(fp, NULL);
		}
		fclose(fp);
		if (ign_openssl_error()) {
			if (_p7)
				PKCS7_free(_p7);
			throw errorEx(tr("Unable to load the PKCS#7 file %1. Tried PEM and DER format.").arg(fname));
		}
		if (p7)
			PKCS7_free(p7);
		p7 = _p7;
	} else
		fopen_error(fname);
}


STACK_OF(X509) *pki_pkcs7::getCertStack()
{
	STACK_OF(X509) *certstack = NULL;
	int i;
        if (p7 == NULL) return NULL;
	i = OBJ_obj2nid(p7->type);
	switch (i) {
		case NID_pkcs7_signed:
			certstack = p7->d.sign->cert;
			break;
		case NID_pkcs7_signedAndEnveloped:
			certstack = p7->d.signed_and_enveloped->cert;
			break;
		default:
			break;
	}
	openssl_error();
	return certstack;
}

void pki_pkcs7::addCert(pki_x509 *crt) {
	if (p7 == NULL || crt == NULL) return;
	PKCS7_add_certificate(p7, crt->getCert());
	openssl_error();
}

