/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "load_obj.h"
#include "pki_x509.h"
#include "pki_key.h"
#include "pki_x509req.h"
#include "pki_pkcs7.h"
#include "pki_pkcs12.h"
#include "pki_multi.h"
#include "pki_temp.h"
#include "pki_crl.h"

load_base::load_base()
{
	filter = QObject::tr("All files ( * )");
	caption = "";
}

pki_base *load_base::loadItem(QString s)
{
	pki_base *pki = newItem();
	if (!pki)
		return NULL;
	try {
		pki->fload(s);
	}
	catch (errorEx &err){
		delete pki;
		throw err;
	}
	return pki;
}

pki_base * load_base::newItem()
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
	filter = QObject::tr("PKI Keys ( *.pem *.der *.key );;"
			"PKCS#8 Keys ( *.p8 *.pk8 );;"
			"SSH Public Keys ( *.pub );;") + filter;
	caption = QObject::tr("Import RSA key");
}

pki_base * load_key::newItem()
{
	return new pki_evp();
}

/* Requests */
load_req::load_req()
	:load_base()
{
	filter = QObject::tr("PKCS#10 CSR ( *.pem *.der *.csr );;"
			"Netscape Request ( *.spkac *.spc );;") + filter;
	caption = QObject::tr("Import Request");
}

pki_base * load_req::newItem()
{
	return new pki_x509req();
}

/* Certificates */
load_cert::load_cert()
	:load_base()
{
	filter = QObject::tr("Certificates ( *.pem *.der *.crt *.cer );;") + filter;
	caption = QObject::tr("Import X.509 Certificate");
}

pki_base * load_cert::newItem()
{
	return new pki_x509();
}

/* PKCS#7 Certificates */
load_pkcs7::load_pkcs7()
	:load_base()
{
	filter = QObject::tr("PKCS#7 data ( *.p7s *.p7m *.p7b );;") + filter;
	caption = QObject::tr("Import PKCS#7 Certificates");
}

pki_base * load_pkcs7::newItem()
{
	return new pki_pkcs7();
}

/* PKCS#12 Certificates */
load_pkcs12::load_pkcs12()
	:load_base()
{
	filter = QObject::tr("PKCS#12 Certificates ( *.p12 *.pfx );;") + filter;
	caption = QObject::tr("Import PKCS#12 Private Certificate");
}

pki_base * load_pkcs12::loadItem(QString s)
{
	pki_base *p12 = new pki_pkcs12(s);
	return p12;
}

/* Templates */
load_temp::load_temp()
	:load_base()
{
	filter = QObject::tr("XCA templates ( *.xca );;") + filter;
	caption = QObject::tr("Import XCA Templates");
}

pki_base * load_temp::newItem()
{
	return new pki_temp();
}

/* CRLs */
load_crl::load_crl()
	:load_base()
{
	filter = QObject::tr("Revocation lists ( *.pem *.der *.crl );;") + filter;
	caption = QObject::tr("Import Certificate Revocation List");
}

pki_base * load_crl::newItem()
{
	return new pki_crl();
}

/* Database */
load_db::load_db()
	:load_base()
{
	filter = QObject::tr("XCA Databases ( *.xdb );;") + filter;
	caption = QObject::tr("Open XCA Database");
}

/* Shared library */
load_pkcs11::load_pkcs11()
	:load_base()
{
#ifdef WIN32
	filter = QObject::tr("PKCS#11 library ( *.dll );;") + filter;
#elif defined(Q_WS_MAC)
	filter = QObject::tr("PKCS#11 library ( *.dylib *.so );;") + filter;
#else
	filter = QObject::tr("PKCS#11 library ( *.so );;") + filter;
#endif
	caption = QObject::tr("Open PKCS#11 shared library");
}

/* General PEM loader */
load_pem::load_pem()
	:load_base()
{
	filter = QObject::tr("PEM files ( *.pem );;") + filter;
	caption = QObject::tr("Load PEM encoded file");
}

pki_base *load_pem::newItem()
{
	return new pki_multi();
}
