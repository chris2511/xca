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

#include "x509name.h"

x509name::x509name()
{
	xn = X509_NAME_new();
}

x509name::x509name(const X509_NAME *n)
{
	xn = X509_NAME_dup((X509_NAME *)n);
}

x509name::~x509name()
{
	X509_NAME_free(xn);
}

void x509name::set(const X509_NAME *n)
{
	X509_NAME_free(xn);
	xn = X509_NAME_dup((X509_NAME *)n);
}


QString x509name::subjectOneLine() const
{
	char *x = X509_NAME_oneline(xn, NULL ,0);
	QString ret = x;
	OPENSSL_free(x);
	return ret;
}

QString x509name::getEntryByNid(int nid) const
{
	int len = X509_NAME_get_text_by_NID(xn, nid, NULL, 0);
	char *buf = (char *)OPENSSL_malloc(len);
	QString s;
	X509_NAME_get_text_by_NID(xn, nid, buf, len);
	s = buf;
	OPENSSL_free(buf);
	return s;
}

bool x509name::operator == (const x509name &x) const
{
	return (X509_NAME_cmp(xn, x.xn) == 0);
}

int x509name::entryCount() const
{
	return  X509_NAME_entry_count(xn);
}

void x509name::addEntryByNid(int nid, const QString entry)
{
	if (entry.isEmpty()) return;
	X509_NAME_add_entry_by_NID(xn, nid, 
		MBSTRING_ASC, (unsigned char*)entry.latin1(),-1,-1,0);
}

X509_NAME *x509name::get() const
{
	return X509_NAME_dup(xn);
}
