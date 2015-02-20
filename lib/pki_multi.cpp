/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
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
#include "pki_temp.h"
#include "load_obj.h"
#include "exception.h"
#include "func.h"
#include "widgets/MainWindow.h"
#include <QList>

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

#define D5 "-----"
#define BEGIN D5 "BEGIN "
/* General PEM loader */
static pki_base *pkiByPEM(QString text, int *skip)
{
	int pos;
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

	if (text.startsWith(PEM_STRING_XCA_TEMPLATE D5))
		return new pki_temp();

	if (text.startsWith(PEM_STRING_EVP_PKEY D5) ||
				text.startsWith(PEM_STRING_PUBLIC D5) ||
				text.startsWith(PEM_STRING_RSA D5) ||
				text.startsWith(PEM_STRING_RSA_PUBLIC D5) ||
				text.startsWith(PEM_STRING_DSA D5) ||
				text.startsWith(PEM_STRING_DSA_PUBLIC D5) ||
				text.startsWith(PEM_STRING_ECDSA_PUBLIC D5) ||
				text.startsWith(PEM_STRING_ECPRIVATEKEY D5) ||
				text.startsWith(PEM_STRING_PKCS8 D5) ||
				text.startsWith(PEM_STRING_PKCS8INF D5))
		return new pki_evp();

	return NULL;
}

void pki_multi::fload(const QString fname)
{
	FILE * fp;
	BIO *bio = NULL;

	fp = fopen_read(fname);
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
				if (BIO_seek(bio, pos + startpos) == -1)
					throw errorEx(tr("Seek failed"));
				continue;
			}
			pos += startpos;
			if (BIO_seek(bio, pos) == -1)
				throw errorEx(tr("Seek failed"));
			item->fromPEM_BIO(bio, name);
			if (pos == BIO_tell(bio)) {
				/* No progress, do it manually */
				if (BIO_seek(bio, pos + 1))
					throw errorEx(tr("Seek failed"));
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
	if (multi.size() == 0)
		throw errorEx(tr("No known PEM encoded items found"));
}

void pki_multi::probeAnything(const QString fname)
{
	pki_base *item = NULL;
	load_base *lb;
	QList<load_base *> lbs;

	lbs <<  new load_pem() <<
		new load_cert() << new load_pkcs7() << new load_pkcs12() <<
		new load_crl() <<  new load_req() <<   new load_key() <<
		new load_temp();

	foreach(lb, lbs) {
		try {
			item = lb->loadItem(fname);
			if (item) {
				multi.append(item);
				break;
			}
		} catch (errorEx &err) {
			if (err.info == E_PASSWD) {
				MainWindow::Error(err);
				break;
			}
		}
	}
	while (!lbs.isEmpty())
		delete lbs.takeFirst();
}
