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

#include "x509name.h"
#include <openssl/asn1.h>

x509name::x509name()
{
	xn = X509_NAME_new();
}

x509name::x509name(const X509_NAME *n)
{
	xn = X509_NAME_dup((X509_NAME *)n);
}

x509name::x509name(const x509name &n)
{
	xn = NULL;
	set(n.xn);
}

x509name::~x509name()
{
	X509_NAME_free(xn);
}

x509name &x509name::set(const X509_NAME *n)
{
	if (xn != NULL)
		X509_NAME_free(xn);
	xn = X509_NAME_dup((X509_NAME *)n);
	return *this;
}


QString x509name::oneLine() const
{
	char *x = X509_NAME_oneline(xn, NULL ,0);
	QString ret = x;
	OPENSSL_free(x);
	return ret;
}

QString x509name::getEntryByNid(int nid) const
{
	QString s;
	int len = X509_NAME_get_text_by_NID(xn, nid, NULL, 0) + 1;
	if (len < 2)
		return s;
	char *buf = (char *)OPENSSL_malloc(len);
	X509_NAME_get_text_by_NID(xn, nid, buf, len);
	s = buf;
	OPENSSL_free(buf);
	return s;
}

QString x509name::getEntry(int i) const
{
	QString s;
	char c;
	ASN1_STRING *d;
	if ( i<0 || i>entryCount() ) return s;
	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(xn,i));
	i = d->length - 1;
	c = d->data[i]; // replace the last char by \0
	d->data[i] = '\0'; 
	s = (char *)d->data; // strcopy the data
	d->data[i] = c; // recover last char
	return s + c;
}

void x509name::delEntry(int i)
{
	X509_NAME_delete_entry(xn, i);
}

QStringList x509name::entryList(int i) const
{
	QStringList sl;
	int n = nid(i);
	sl += OBJ_nid2sn(n);
	sl += OBJ_nid2ln(n);
	sl += getEntry(i);
	return sl;
}

int x509name::nid(int i) const
{
	X509_NAME_ENTRY *ne;
	ne = sk_X509_NAME_ENTRY_value(xn->entries, i);
	return OBJ_obj2nid(ne->object);
}				 

unsigned char *x509name::d2i(unsigned char *p, int size)
{
	unsigned char *mp = p;
	d2i_X509_NAME(&xn, &mp, size);
	if (xn == NULL)
		xn = X509_NAME_new();
	return mp;
}

unsigned char *x509name::i2d(unsigned char *p)
{
	unsigned char *mp = p;
	i2d_X509_NAME(xn, &mp);
	return mp;
}					 

bool x509name::operator == (const x509name &x) const
{
	return (X509_NAME_cmp(xn, x.xn) == 0);
}

x509name &x509name::operator = (const x509name &x)
{
	set(x.xn);
	return *this;
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

int x509name::derSize() const
{
	return i2d_X509_NAME(xn, NULL);
}

void x509name::write_fp(FILE *fp) const
{
	int cnt = entryCount();
	for (int i=0; i<cnt; i++) {
		QStringList sl = entryList(i);
		fprintf(fp, "%s=%s\n",sl[0].latin1(), sl[2].latin1());
	}
}

void x509name::read_fp(FILE *fp)
{
	char buf[180];
	QStringList sl;
	QString line = fgets(buf, 180, fp);
	sl.split('=', line),
	addEntryByNid(OBJ_sn2nid(sl[0].latin1()), sl[1]);
}
