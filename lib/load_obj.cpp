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
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
 *
 *	http://www.trolltech.com
 * 
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
	filter.clear();
	filter.prepend( QObject::tr("All Files ( *.* )") );
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
	filter.prepend( "PKI Keys ( *.pem *.der *.key )");
	filter.prepend( "PKCS#8 Keys ( *.p8 *.pk8 )");
	caption = QObject::tr("Import RSA key");
}		

pki_base * load_key::loadItem(QString s)
{
	pki_base *lkey = new pki_key(s, &MainWindow::passRead);
	return lkey;
};

/* Requests */
load_req::load_req()
	:load_base()
{
	filter.prepend( QObject::tr("PKCS#10 CSR ( *.pem *.der *.csr )"));
	caption = QObject::tr("Import Request");
}		

pki_base * load_req::loadItem(QString s)
{
	pki_base *req = new pki_x509req(s);
	return req;
};

/* Certificates */
load_cert::load_cert()
	:load_base()
{
	filter.prepend(QObject::tr("Certificates ( *.pem *.der *.crt *.cer )"));
	caption = QObject::tr("Import X.509 Certificate");
}		

pki_base * load_cert::loadItem(QString s)
{
	pki_base *crt = new pki_x509(s);
	return crt;
};

/* PKCS#7 Certificates */
load_pkcs7::load_pkcs7()
	:load_base()
{
	filter.prepend(QObject::tr("PKCS#7 data ( *.p7s *.p7m *.p7b )"));
	caption = QObject::tr("Import PKCS#7 Certificates");
}		

pki_base * load_pkcs7::loadItem(QString s)
{
	pki_pkcs7 *p7 = new pki_pkcs7(s);
	try {
		p7->readP7(s);
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
	filter.prepend(QObject::tr("PKCS#12 Certificates ( *.p12 *.pfx )"));
	caption = QObject::tr("Import PKCS#12 Private Certificate");
}		

pki_base * load_pkcs12::loadItem(QString s)
{
	pki_base *p12 = new pki_pkcs12(s, &MainWindow::passRead);
	return p12;
};

/* Templates */
load_temp::load_temp()
	:load_base()
{
	filter.prepend(QObject::tr("XCA templates ( *.xca )"));
	caption = QObject::tr("Import XCA Templates");
}		

pki_base * load_temp::loadItem(QString s)
{
	pki_temp *temp = new pki_temp(s);
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
	filter.prepend(QObject::tr("Revokation lists ( *.pem *.crl )"));
	caption = QObject::tr("Import Certificate Revokation List");
}		

pki_base * load_crl::loadItem(QString s)
{
	pki_crl *crl = new pki_crl(s);
	return crl;
};


