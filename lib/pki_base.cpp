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


#include "pki_base.h"
#include "exception.h"

int pki_base::pki_counter = 0;

pki_base::pki_base(const QString d)
{
	desc = d;
	class_name = "pki_base";
	pointer = NULL;
	pki_counter++;
}

pki_base::pki_base()
{
	desc = "";
	class_name = "pki_base";
	pointer=NULL;
	pki_counter++;
}

pki_base::~pki_base(void)
{
	pki_counter--;
}


QString pki_base::getIntName()
{
	return desc;
}

int pki_base::get_pki_counter()
{
	return pki_counter;
}

QString pki_base::getClassName()
{
	return class_name;
}

void pki_base::setIntName(const QString d)
{
	desc = d.latin1();
}

void pki_base::fopen_error(const QString fname)
{
	QString txt = "Error opening file: '" + fname + "'";
	openssl_error(txt);
}


void pki_base::openssl_error(const QString myerr)  const
{
	QString errtxt = "";
	QString error = "";
	if (myerr != "") {
		CERR("PKI ERROR: " << myerr);
		error += myerr + "\n";
	}
	while (int i = ERR_get_error() ) {
	   errtxt = ERR_error_string(i ,NULL);
	   CERR("OpenSSL: " << errtxt);
	   error += errtxt + "\n";
	}
	if (!error.isEmpty()) {
		throw errorEx(error, class_name);
	}
}


bool pki_base::ign_openssl_error() const 
{
	// ignore openssl errors
	QString errtxt;
	while (int i = ERR_get_error() ) {
	   errtxt = ERR_error_string(i ,NULL);
	   CERR("IGNORE -> OpenSSL: " << errtxt << " <- IGNORE");
	}
	return !errtxt.isEmpty();
}

int pki_base::intToData(unsigned char **p, const int val)
{
	int s = sizeof(int);
	memcpy(*p, &val, s);
	*p += s;
	return s;
}

int pki_base::intFromData(unsigned char **p)
{
	int s = sizeof(int);
	int ret;
	memcpy(&ret, *p, s);
	*p += s;
	return ret;
}

int pki_base::boolToData(unsigned char **p, const bool val)
{
	int s = sizeof(bool);
	memcpy(*p, &val, s);
	*p += s;
	return s;
}

bool pki_base::boolFromData(unsigned char **p)
{
	int s = sizeof(bool);
	bool ret;
	memcpy(&ret, *p, s);
	*p += s;
	return ret;
}

int pki_base::stringToData(unsigned char **p, const QString val)
{
	int s = (val.length() +1) * sizeof(char);
	memcpy(*p, val.latin1(), s);
	*p += s;
	return s;
}

QString pki_base::stringFromData(unsigned char **p)
{
	QString ret="";
	while(**p) {
		ret +=(char)**p;
		*p += sizeof(char);
	}
	*p += sizeof(char);
	return ret;
}

QString pki_base::rmslashdot(const QString &s)
{
	int r = s.findRev('.');
#ifdef WIN32
	int l = s.findRev('\\');
#else
	int l = s.findRev('/');
#endif
        return s.mid(l+1,r-l-1);
}							       

void pki_base::updateView()
{
	if (pointer == NULL) return;
#ifdef qt3
	pointer->setRenameEnabled(0,true);
#endif
	pointer->setText(0, getIntName());
}

