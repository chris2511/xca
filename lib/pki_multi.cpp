/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_multi.h"
#include "pki_x509.h"
#include "pki_key.h"
#include "pki_x509req.h"
#include "pki_pkcs7.h"
#include "pki_pkcs12.h"
#include "pki_crl.h"
#include "exception.h"
#include "widgets/MainWindow.h"

pki_multi::pki_multi(const QString name)
	:pki_base(name)
{
	multi.clear();
	class_name="pki_multi";
}

pki_multi::~pki_multi()
{
	pki_base *pki;
	while ((pki = pull()))
		delete pki;
}

pki_base *pki_multi::pull()
{
	if (multi.isEmpty())
		return NULL;
	return multi.takeFirst();
}

/* General PEM loader */
static pki_base *pkiByPEM(QString text, int *skip)
{
	int pos;
#define D5 "-----"
#define BEGIN D5 "BEGIN "
	pos = text.indexOf(BEGIN);
	if (pos <0) {
		if (skip)
			*skip = text.length() - (sizeof(BEGIN)-1);
		return NULL;
	}
	if (skip) {
		*skip = pos;
		if (pos) /* if we are not at the beginning, retry */
			return NULL;
	}

	text = text.remove(0, pos + sizeof(BEGIN)-1);
	if (text.startsWith(PEM_STRING_X509_OLD D5) ||
				text.startsWith(PEM_STRING_X509 D5) ||
				text.startsWith(PEM_STRING_X509_TRUSTED D5))
		return new pki_x509();

	if (text.startsWith(PEM_STRING_PKCS7 D5))
		return new pki_pkcs7();

	if (text.startsWith(PEM_STRING_X509_REQ_OLD D5) ||
				text.startsWith(PEM_STRING_X509_REQ D5))
		return new pki_x509req();

	if (text.startsWith(PEM_STRING_X509_CRL D5))
		return new pki_crl();

	if (text.startsWith(PEM_STRING_EVP_PKEY D5) ||
				text.startsWith(PEM_STRING_PUBLIC D5) ||
				text.startsWith(PEM_STRING_RSA D5) ||
				text.startsWith(PEM_STRING_RSA_PUBLIC D5) ||
				text.startsWith(PEM_STRING_DSA D5) ||
				text.startsWith(PEM_STRING_DSA_PUBLIC D5) ||
				text.startsWith(PEM_STRING_PKCS8 D5) ||
				text.startsWith(PEM_STRING_PKCS8INF D5))
		return new pki_key();

	return NULL;
}

void pki_multi::fload(const QString fname)
{
	FILE * fp;
	BIO *bio = NULL;

	fp = fopen(CCHAR(fname), "r");
	if (!fp) {
		fopen_error(fname);
		return;
	}
	bio = BIO_new_fp(fp, BIO_CLOSE);
	fromPEM_BIO(bio, fname);
	BIO_free(bio);
};

#define BUFLEN 1024
void pki_multi::fromPEM_BIO(BIO *bio, QString name)
{
	QString text;
	pki_base *item = NULL;
	char buf[BUFLEN];
	int len, startpos;
	for (;;) {
		try {
			int pos = BIO_tell(bio);
			len = BIO_read(bio, buf, BUFLEN-1);
			buf[len] = '\0';
			text = buf;
			item = pkiByPEM(text, &startpos);
			if (!item) {
				if (startpos <= 0)
					break;
				BIO_seek(bio, pos + startpos);
				continue;
			}
			pos += startpos;
			BIO_seek(bio, pos);
			item->fromPEM_BIO(bio, name);
			if (pos == BIO_tell(bio)) {
				/* No progress, do it manually */
				BIO_seek(bio, pos + 1);
				printf("Could not load: %s\n",
						CCHAR(item->getClassName()));
				delete item;
				continue;
			}
			openssl_error();
			multi.append(item);
		} catch (errorEx &err) {
			MainWindow::Error(err);
			if (item)
				delete item;
			item = NULL;
		}
	}
}