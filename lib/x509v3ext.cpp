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

#include "x509v3ext.h"
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <qstringlist.h>

x509v3ext::x509v3ext()
{
	ext = X509_EXTENSION_new();
}

x509v3ext::x509v3ext(const X509_EXTENSION *n)
{
	ext = X509_EXTENSION_dup((X509_EXTENSION *)n);
}

x509v3ext::x509v3ext(const x509v3ext &n)
{
	ext = NULL;
	set(n.ext);
}

x509v3ext::~x509v3ext()
{
	X509_EXTENSION_free(ext);
}

x509v3ext &x509v3ext::set(const X509_EXTENSION *n)
{
	if (ext != NULL)
		X509_EXTENSION_free(ext);
	ext = X509_EXTENSION_dup((X509_EXTENSION *)n);
	return *this;
}

x509v3ext &x509v3ext::create(int nid, const QString &et, X509V3_CTX *ctx)
{
	if (ext) {
		X509_EXTENSION_free(ext);
		ext = NULL;
	}
	if (!et.isEmpty()) {
		ext = X509V3_EXT_conf_nid(NULL, ctx, nid, (char *)et.latin1());
	}
	if (!ext) ext = X509_EXTENSION_new();
	return *this;
}

int x509v3ext::nid() const
{
	ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
	return OBJ_obj2nid(obj);
}

void *x509v3ext::d2i()
{
	return X509V3_EXT_d2i(ext);
}
		  
/*	
bool x509v3ext::operator == (const x509v3ext &x) const
{
	return (X509_EXTENSION_cmp(ext, x.ext) == 0);
}
*/
x509v3ext &x509v3ext::operator = (const x509v3ext &x)
{
	set(x.ext);
	return *this;
}

QString x509v3ext::getObject() const
{
	QString a = OBJ_nid2ln(nid());
	return a;
}

int x509v3ext::getCritical() const
{
	return X509_EXTENSION_get_critical(ext);
}

QString x509v3ext::getValue() const
{
#define V3_BUF 100
	QString text = "";
	int len,cn=0;
	char buffer[V3_BUF+1];
	BIO *bio = BIO_new(BIO_s_mem());
#if OPENSSL_VERSION_NUMBER >= 0x0090700fL	
	if(!X509V3_EXT_print(bio, ext, X509V3_EXT_PARSE_UNKNOWN, 0))
#else
	if (!X509V3_EXT_print(bio, ext, 0, 0))
#endif
		return text;
	do {
		len = BIO_read(bio, buffer, V3_BUF);
		if (len < 0) break;
		buffer[len] = '\0';
		text+=buffer;
	} while (len == V3_BUF);
#undef V3_BUF	 
	return text;
}

QString x509v3ext::getHtml() const
{
	QString html;
	html = "<b><u>" + getObject();
	if (getCritical() != 0)
		html += " <font color=\"red\">critical</font>";
	html += ":</u></b><br><tt>" + getValue() + "</tt>";
	return html;
}
	
X509_EXTENSION *x509v3ext::get() const
{
	return X509_EXTENSION_dup(ext);
}

bool x509v3ext::isValid() const
{
	return ext->value->length > 0;
}

/*************************************************************/

void extList::setStack(STACK_OF(X509_EXTENSION) *st)
{
	clear();
	int cnt = sk_X509_EXTENSION_num(st);
	x509v3ext e;
	for (int i=0; i<cnt; i++) {
		e.set(sk_X509_EXTENSION_value(st,i));
		append(e);
	}
}

STACK_OF(X509_EXTENSION) *extList::getStack()
{
	STACK_OF(X509_EXTENSION) *sk;
	sk = sk_X509_EXTENSION_new_null();
	for (unsigned int i=0; i< count(); i++) {
		sk_X509_EXTENSION_push(sk, operator[](i).get());
	}
	return sk;		
}

QString extList::getHtml(const QString &sep)
{
	x509v3ext e;	
	QStringList s;
	for (unsigned int i=0; i< count(); i++)
		s << operator[](i).getHtml();
	QString a = s.join(sep);
	return a;
}

int extList::delByNid(int nid)
{
	int removed=0;
	extList::Iterator it;
	for( it = begin(); it != end(); ++it ) {
		if ((*it).nid() == nid) {
			printf("Removing: %s\n", (*it).getValue().latin1());
			remove(it);
			it = begin();
			removed=1;
		}
	}
	return removed;
}
