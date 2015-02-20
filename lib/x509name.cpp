/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QMessageBox>
#include "x509name.h"
#include "base.h"
#include "func.h"
#include <openssl/asn1.h>
#include <openssl/err.h>
#include "exception.h"

x509name::x509name()
{
	xn = X509_NAME_new();
}

x509name::x509name(const X509_NAME *n)
{
	xn = X509_NAME_dup((X509_NAME *)n);
}

x509name::x509name(STACK_OF(X509_NAME_ENTRY) *entries)
{
	X509_NAME *n = X509_NAME_new();
	STACK_OF(X509_NAME_ENTRY) *ba = n->entries;
	xn = NULL;
	n->entries = entries;
	set(n);
	n->entries = ba;
	X509_NAME_free(n);
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

QString x509name::oneLine(unsigned long flags) const
{
	QString ret;
	long l;
	const char *p;
	BIO *mem = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(mem, xn, 0, flags);
	l = BIO_get_mem_data(mem, &p);
	ret = ret.fromUtf8(p,l);
	BIO_free(mem);
	return ret;
}

QString x509name::getEntryByNid(int nid) const
{
	int i = X509_NAME_get_index_by_NID(xn, nid, -1);
	if (i < 0)
		return QString::null;
	return getEntry(i);
}

QString x509name::getMostPopular() const
{
	static const int nids[] = { NID_commonName, NID_pkcs9_emailAddress,
			NID_organizationalUnitName, NID_organizationName };
	int pos = -1;

	for (unsigned i = 0; i < ARRAY_SIZE(nids) && pos < 0; i++) {
		pos = X509_NAME_get_index_by_NID(xn, nids[i], -1);
	}
	if (pos < 0)
		pos = 0;
	return getEntry(pos);
}

QString x509name::getEntry(int i) const
{
	QString ret;
	ASN1_STRING *d;

	if ( i<0 || i>entryCount() )
		return ret;

	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(xn,i));

	return asn1ToQString(d);
}

QString x509name::getEntryTag(int i) const
{
	QString s = QObject::tr("Invalid");
	ASN1_STRING *d;

	if (i<0 || i>=entryCount())
		i = entryCount() - 1;
	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(xn,i));

	if (!d)
		return s;

	s = ASN1_tag2str(d->type);
	return s;
}

QString x509name::popEntryByNid(int nid)
{
	int i = X509_NAME_get_index_by_NID(xn, nid, -1);
	if (i < 0)
		return QString::null;
	QString n = getEntry(i);
	X509_NAME_delete_entry(xn, i);
	return n;
}

QString x509name::hash() const
{
	return QString("%1").arg(X509_NAME_hash(xn), 8, 16, QChar('0'));
}

QStringList x509name::entryList(int i) const
{
	QStringList sl;
	int n = nid(i);
	if (n == NID_undef) {
		QString oid = getOid(i);
		sl << oid << oid;
	} else {
		sl << OBJ_nid2sn(n) << OBJ_nid2ln(n);
	}
	sl << getEntry(i) << getEntryTag(i);
	return sl;
}

int x509name::nid(int i) const
{
	X509_NAME_ENTRY *ne;

	ne = sk_X509_NAME_ENTRY_value(xn->entries, i);
	if (ne == NULL)
		return NID_undef;
	return OBJ_obj2nid(ne->object);
}

QString x509name::getOid(int i) const
{
	X509_NAME_ENTRY *ne;

	ne = sk_X509_NAME_ENTRY_value(xn->entries, i);
	if (ne == NULL)
		return QString();
	return OBJ_obj2QString(ne->object, 1);
}

void x509name::d2i(QByteArray &ba)
{
	X509_NAME *n = (X509_NAME*)d2i_bytearray(D2I_VOID(d2i_X509_NAME), ba);
	if (n) {
		X509_NAME_free(xn);
		xn = n;
	}
}

QByteArray x509name::i2d()
{
	 return i2d_bytearray(I2D_VOID(i2d_X509_NAME), xn);
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
	return OBJ_txt2nid(nid_name.toLatin1());
}

QString x509name::checkLength() const
{
	ASN1_STRING_TABLE *tab;
	int i, max = entryCount();
	QString warn;

	for (i=0; i<max; i++) {
		int n = nid(i);
		QString entry;

		tab = ASN1_STRING_TABLE_get(n);
		if (!tab)
			continue;
		entry = getEntry(i);
		if (tab->minsize > entry.size()) {
			warn += QObject::tr("%1 is shorter than %2 bytes: '%3'").
				arg(OBJ_nid2ln(n)).arg(tab->maxsize).arg(entry);
			warn += "\n";
		}
		if ((tab->maxsize != -1) && (tab->maxsize < entry.size())) {
			warn += QObject::tr("%1 is longer than %2 bytes: '%3'").
				arg(OBJ_nid2ln(n)).arg(tab->maxsize).arg(entry);
			warn += "\n";
		}
	}
	return warn;
}

bool x509name::search(const QRegExp &pattern)
{
	int i, max = entryCount();
	for (i=0; i<max; i++) {
		if (getEntry(i).contains(pattern))
			return true;
	}
	return false;
}

QString x509name::taggedValues() const
{
	int i, max = entryCount();
	QString ret;

	for (i=0; i<max; i++) {
		int n = nid(i);
		ret += QString("%1.%2=%3\n").
			arg(i).arg(OBJ_nid2sn(n)).arg(getEntry(i));
	}
	return ret;
}

void x509name::addEntryByNid(int nid, const QString entry)
{
	if (entry.isEmpty())
		return;
	ASN1_STRING *a = QStringToAsn1(entry, nid);
	X509_NAME_add_entry_by_NID(xn, nid, a->type, a->data, a->length, -1, 0);
	ASN1_STRING_free(a);
	openssl_error(QString("'%1' (%2)").arg(entry).arg(OBJ_nid2ln(nid)));
}

X509_NAME *x509name::get() const
{
	return X509_NAME_dup(xn);
}

