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
 * $id$
 *
 */                           


#include "pki_base.h"


pki_base::pki_base(const string d)
{
	error = "";
	desc = d;
}

pki_base::pki_base()
{
	error = "";
	desc = "";
}

pki_base::~pki_base(void)
{}


string pki_base::getDescription()
{
	string x = desc;
	return x;
}


string pki_base::getError()
{
	string x = error;
	error = "";
	return x;
}


void pki_base::setDescription(const string d)
{
	desc = d;
}


bool pki_base::pki_error(const string myerr)
{
	string errtxt = "";
	if (myerr != "") {
		CERR << "PKI: " << myerr << endl;
		error += myerr + "\n";
	}
	return openssl_error();
}


bool pki_base::openssl_error()
{
	string errtxt = "";
	while (int i = ERR_get_error() ) {
	   errtxt = ERR_error_string(i ,NULL);
	   CERR << "OpenSSL: " << errtxt << endl;
	   error += errtxt + "\n";
	}
	return  (!error.empty());
}


bool pki_base::ign_openssl_error()
{
	// ignore openssl errors
	bool ret = false;
	string errtxt;
	while (int i = ERR_get_error() ) {
	   ret = true;
	   errtxt = ERR_error_string(i ,NULL);
	   CERR << "IGNORE: OpenSSL: " << errtxt << endl;
	}
	return ret;
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

