/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 *	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */


#include "load_obj.h"
#include "pki_x509.h"
#include "pki_key.h"
#include "pki_x509req.h"
#include "pki_pkcs7.h"
#include "pki_pkcs12.h"
#include "widgets/MainWindow.h"

load_base::load_base()
{
	filter = QObject::tr("All files ( *.* )");
	caption = "";
}

pki_base * load_base::loadItem(QString s)
{
	return NULL;
}

load_base::~load_base()
{
}

/* Keys */
load_key::load_key()
	:load_base()
{
	filter = QObject::tr("PKCS#8 Keys ( *.p8 *.pk8 );;"
			"PKI Keys ( *.pem *.der *.key );;") + filter;
	caption = QObject::tr("Import RSA key");
}

pki_base * load_key::loadItem(QString s)
{
	pki_key *lkey = new pki_key();
	if (lkey)
		lkey->fload(s);
	return lkey;
};

/* Requests */
load_req::load_req()
	:load_base()
{
	filter = QObject::tr("Netscape Request ( *.spkac *.spc );;"
			"PKCS#10 CSR ( *.pem *.der *.csr );;") + filter;
	caption = QObject::tr("Import Request");
}

pki_base * load_req::loadItem(QString s)
{
	pki_x509req *req = new pki_x509req(s);
	if (!req)
		return NULL;
	try {
		req->fload(s);
	}
	catch (errorEx &err){
		delete req;
		throw err;
	}
	return req;
};

/* Certificates */
load_cert::load_cert()
	:load_base()
{
	filter = QObject::tr("Certificates ( *.pem *.der *.crt *.cer );;") + filter;
	caption = QObject::tr("Import X.509 Certificate");
}

pki_base * load_cert::loadItem(QString s)
{
	pki_x509 *crt = new pki_x509(s);
	if (!crt)
		return NULL;
	try {
		crt->fload(s);
	}
	catch (errorEx &err){
		delete crt;
		throw err;
	}
	return crt;
};

/* PKCS#7 Certificates */
load_pkcs7::load_pkcs7()
	:load_base()
{
	filter = QObject::tr("PKCS#7 data ( *.p7s *.p7m *.p7b );;") + filter;
	caption = QObject::tr("Import PKCS#7 Certificates");
}

pki_base * load_pkcs7::loadItem(QString s)
{
	pki_pkcs7 *p7 = new pki_pkcs7(s);
	if (!p7)
		return NULL;
	try {
		p7->fload(s);
	}
	catch (errorEx &err){
		delete p7;
		throw err;
	}
	return p7;
};

/* PKCS#12 Certificates */
load_pkcs12::load_pkcs12()
	:load_base()
{
	filter = QObject::tr("PKCS#12 Certificates ( *.p12 *.pfx );;") + filter;
	caption = QObject::tr("Import PKCS#12 Private Certificate");
}

pki_base * load_pkcs12::loadItem(QString s)
{
	pki_base *p12 = new pki_pkcs12(s, MainWindow::passRead);
	return p12;
};

/* Templates */
load_temp::load_temp()
	:load_base()
{
	filter = QObject::tr("XCA templates ( *.xca );;") + filter;
	caption = QObject::tr("Import XCA Templates");
}

pki_base * load_temp::loadItem(QString s)
{
	pki_temp *temp = new pki_temp(s);
	if (!temp)
		return NULL;
	try {
		temp->loadTemp(s);
	}
	catch (errorEx &err){
		delete temp;
		throw err;
	}
	return temp;
};

/* CRLs */
load_crl::load_crl()
	:load_base()
{
	filter = QObject::tr("Revocation lists ( *.pem *.der *.crl );;") + filter;
	caption = QObject::tr("Import Certificate Revocation List");
}

pki_base * load_crl::loadItem(QString s)
{
	pki_crl *crl = new pki_crl(s);
	if (!crl)
		return NULL;
	try {
		crl->fload(s);
	}
	catch (errorEx &err){
		delete crl;
		throw err;
	}
	return crl;
};

/* Database */
load_db::load_db()
	:load_base()
{
	filter = QObject::tr("XCA Databases ( *.xdb );;") + filter;
	caption = QObject::tr("Open XCA Database");
}

/* General PEM loader */
static load_base *getload(QString text)
{
	int pos;
#define D5 "-----"
	pos = text.indexOf(D5 "BEGIN ");
	if (pos <0)
		return NULL;
	text = text.remove(0, pos + 11);
	printf("Text B: %s\n", CCHAR(text));
	if (text.startsWith(PEM_STRING_X509_OLD D5) ||
				text.startsWith(PEM_STRING_X509 D5) ||
				text.startsWith(PEM_STRING_X509_TRUSTED D5))
		return new load_cert();

	if (text.startsWith(PEM_STRING_PKCS7 D5))
		return new load_pkcs7();
	
	if (text.startsWith(PEM_STRING_X509_REQ_OLD D5) ||
				text.startsWith(PEM_STRING_X509_REQ D5))
		return new load_req();

	if (text.startsWith(PEM_STRING_X509_CRL D5))
		return new load_crl();

	if (text.startsWith(PEM_STRING_EVP_PKEY D5) ||
				text.startsWith(PEM_STRING_PUBLIC D5) ||
				text.startsWith(PEM_STRING_RSA D5) ||
				text.startsWith(PEM_STRING_RSA_PUBLIC D5) ||
				text.startsWith(PEM_STRING_DSA D5) ||
				text.startsWith(PEM_STRING_DSA_PUBLIC D5) ||
				text.startsWith(PEM_STRING_PKCS8 D5) ||
				text.startsWith(PEM_STRING_PKCS8INF D5))
		return new load_key();

	return NULL;
}

load_pem::load_pem()
	:load_base()
{
	filter = QObject::tr("Pem files ( *.pem );;") + filter;
	caption = QObject::tr("Load PEM encoded file");
}

pki_base * load_pem::loadItem(QString fname)
{
	char buf[100];
	int len;
	FILE * fp;
	QString text;
	pki_base *item = NULL;
	load_base *lb = NULL;

	try {
		fp = fopen(CCHAR(fname), "r");
		if (!fp) 
			throw errorEx(QObject::tr("File open error: ") + fname);
		len = fread(buf, 1, 99, fp);
		fclose(fp);
		if (len < 11)
			throw errorEx(QObject::tr("File corrupted: ") + fname);
		buf[len] = '\0';
		text = buf;
		lb = getload(text);
		if (!lb)
			throw errorEx(QObject::tr("Unknown PEM file: ") + fname);
		printf("CAPTION = '%s' for %s \n", CCHAR(lb->caption),
			CCHAR(fname));
		item = lb->loadItem(fname);
		delete lb;
		printf("LOAD success: %s\n", CCHAR(fname));
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
		if (item)
			delete item;
		item = NULL;
		if (lb)
			delete lb;
	}
	return item;
};
