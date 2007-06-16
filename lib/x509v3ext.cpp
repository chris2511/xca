/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "x509v3ext.h"
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <qstringlist.h>
#include "base.h"

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
	X509_EXTENSION *new_ext = NULL;
	if (!et.isEmpty()) {
		new_ext = X509V3_EXT_conf_nid(NULL, ctx, nid, (char*)CCHAR(et));
	}
	if (new_ext) {
		X509_EXTENSION_free(ext);
		ext = new_ext;
	}
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
	QString text = "";
	int ret;
	char *p = NULL;
	BIO *bio = BIO_new(BIO_s_mem());

	ret = X509V3_EXT_print(bio, ext, X509V3_EXT_DEFAULT, 0);
	if (ret) {
		long len = BIO_get_mem_data(bio, &p);
		text = QString::fromLocal8Bit(p, len);
	}
	BIO_free(bio);
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
	for (int i=0; i< count(); i++) {
		sk_X509_EXTENSION_push(sk, operator[](i).get());
	}
	return sk;
}

QString extList::getHtml(const QString &sep)
{
	x509v3ext e;
	QStringList s;
	for (int i=0; i< size(); i++)
		s << at(i).getHtml();
	QString a = s.join(sep);
	return a;
}

int extList::delByNid(int nid)
{
	int removed=0;
	for(int i = 0; i< size(); i++) {
		if (at(i).nid() == nid) {
			removeAt(i);
			removed=1;
		}
	}
	return removed;
}

int extList::delInvalid(void)
{
	int removed=0;
	for(int i = 0; i<size(); i++) {
		if (!at(i).isValid()) {
			removeAt(i);
			removed=1;
			i--;
		}
	}
	return removed;
}
