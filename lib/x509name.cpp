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
	ASN1_OBJECT *obj;
	obj=OBJ_nid2obj(nid);
	if (obj == NULL) return QString::null;
	int i=X509_NAME_get_index_by_OBJ(xn,obj,-1);
	ASN1_OBJECT_free(obj);
	if (i < 0) return QString::null;
	return getEntry(i);
}

QString x509name::getEntry(int i) const
{
	QString s;
	ASN1_STRING *d;
	if ( i<0 || i>entryCount() ) return s;
	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(xn,i));

	QString ret;

	if (d->type == V_ASN1_BMPSTRING) {
	  for (int i=0;i<d->length;i+=2)
		ret+=QChar((unsigned short)d->data[i]*256+
			   (unsigned short)d->data[i+1]   );
	}
	else if (d->type == V_ASN1_UTF8STRING)
		ret=QString::fromUtf8((const char *)d->data,d->length);
	else
		ret=QString::fromLatin1((const char *)d->data,d->length);
	
	return ret;
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
	X509_NAME *xn_sik = xn;
	xn = d2i_X509_NAME(NULL, &mp, size);
	if (xn == NULL)
		xn = xn_sik;
	else
		X509_NAME_free(xn_sik);
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

int x509name::getNidByName(const QString &nid_name)
{
 	return OBJ_txt2nid((char*)nid_name.latin1());
}

static int fix_data(int nid, int *type)
{
	if (nid == NID_pkcs9_emailAddress)
		*type=V_ASN1_IA5STRING;
	if ((nid == NID_commonName) && (*type == V_ASN1_IA5STRING))
		*type=V_ASN1_T61STRING;
	if ((nid == NID_pkcs9_challengePassword) && (*type == V_ASN1_IA5STRING))
		*type=V_ASN1_T61STRING;
	if ((nid == NID_pkcs9_unstructuredName) && (*type == V_ASN1_T61STRING))
		return(0);
	if (nid == NID_pkcs9_unstructuredName)
		*type=V_ASN1_IA5STRING;
	return 1;
}

void x509name::addEntryByNid(int nid, const QString entry)
{
	if (entry.isEmpty()) return;

	// check for a UNICODE-String.
	bool need_uc=false;

	for (unsigned i=0;i<entry.length();i++)
		if(entry.at(i).unicode()>127) { need_uc=true; break; }

	if (need_uc) {
		unsigned char *data = (unsigned char *)OPENSSL_malloc(entry.length()*2);

		for (unsigned i=0;i<entry.length();i++) {
			data[2*i] = entry.at(i).unicode() >> 8;
			data[2*i+1] = entry.at(i).unicode() & 0xff;
		}

		X509_NAME_add_entry_by_NID(xn, nid, V_ASN1_BMPSTRING,
					   data,entry.length()*2,-1,0);
		OPENSSL_free(data);
	}
	else {
		int type=ASN1_PRINTABLE_type((unsigned char *)entry.latin1(),-1);

		if (fix_data(nid, &type) == 0)
			return;

		X509_NAME_add_entry_by_NID(xn, nid, type,
					   (unsigned char*)entry.latin1(),-1,-1,0);
	}
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
