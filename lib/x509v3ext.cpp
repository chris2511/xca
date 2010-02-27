/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
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
	if (ext) {
		X509_EXTENSION_free(ext);
		ext = NULL;
	}
	if (!et.isEmpty()) {
		ext = X509V3_EXT_conf_nid(NULL, ctx, nid, (char*)CCHAR(et));
	}
	if (!ext)
		ext = X509_EXTENSION_new();
	else {
		if (ctx && ctx->subject_cert) {
			STACK_OF(X509_EXTENSION) **sk;
			sk = &ctx->subject_cert->cert_info->extensions;
			X509v3_add_ext(sk, ext, -1);
		}
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

QString x509v3ext::getValue(bool html) const
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
	if (html) {
		text.replace(QRegExp("&"), "&amp;");
		text.replace(QRegExp("<"), "&lt;");
		text.replace(QRegExp(">"), "&gt;");
	}
	return text.trimmed();
}

static void *ext_str_new(X509_EXTENSION *ext)
{
	const X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);
	const unsigned char *p = ext->value->data;
	void *ext_str;

	if(method->it)
		ext_str = ASN1_item_d2i(NULL, &p, ext->value->length, ASN1_ITEM_ptr(method->it));
        else
		ext_str = method->d2i(NULL, &p, ext->value->length);
	return ext_str;
}

static void ext_str_free(X509_EXTENSION *ext, void *ext_str)
{
	const X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);

	if (method->it)
		ASN1_item_free((ASN1_VALUE*)ext_str,ASN1_ITEM_ptr(method->it));
	else
		method->ext_free(ext_str);
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define C_X509V3_EXT_METHOD const X509V3_EXT_METHOD
#else
#define C_X509V3_EXT_METHOD X509V3_EXT_METHOD
#endif

QString x509v3ext::i2s()
{
	QString str;
	C_X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);
	void *ext_str = ext_str_new(ext);

	if (!ext_str)
		return str;
	if (method->i2s)
		str = QString(method->i2s(method, ext_str));

	ext_str_free(ext, ext_str);
	return str;
}

QStringList x509v3ext::i2v()
{
	C_X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);
	void *ext_str = ext_str_new(ext);
	QStringList sl;

	if (!ext_str)
		return sl;
	if (method->i2v) {
		STACK_OF(CONF_VALUE) *val = method->i2v(method, ext_str, NULL);
		for (int i = 0; i < sk_CONF_VALUE_num(val); i++) {
			CONF_VALUE *nval = sk_CONF_VALUE_value(val, i);
			const char *name = nval->name;
			if (name) {
				if (!strcmp(name, "IP Address"))
					name = "IP";
				else if (!strcmp(name, "Registered ID"))
					name = "RID";
			}
			if (!name)
				sl << QString(nval->value);
			else if (!nval->value)
				sl << QString(name);
			else
				sl << QString("%1:%2").arg(name).arg(nval->value);
		}
		sk_CONF_VALUE_pop_free(val, X509V3_conf_free);
	}

	ext_str_free(ext, ext_str);
	return sl;
}

QString x509v3ext::getHtml() const
{
	QString html;
	html = "<b><u>" + getObject();
	if (getCritical() != 0)
		html += " <font color=\"red\">critical</font>";
	html += ":</u></b><br><tt>" + getValue(true) + "</tt>";
	return html;
}

X509_EXTENSION *x509v3ext::get() const
{
	return X509_EXTENSION_dup(ext);
}

bool x509v3ext::isValid() const
{
	return ext->value->length > 0 &&
		OBJ_obj2nid(ext->object) != NID_undef;
}

/*************************************************************/

void extList::setStack(STACK_OF(X509_EXTENSION) *st, int start)
{
	clear();
	int cnt = sk_X509_EXTENSION_num(st);
	x509v3ext e;
	for (int i=start; i<cnt; i++) {
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

int extList::idxByNid(int nid)
{
	for(int i = 0; i< size(); i++) {
		if (at(i).nid() == nid) {
			return i;
		}
	}
	return -1;
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
