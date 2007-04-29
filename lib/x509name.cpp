/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "x509name.h"
#include "base.h"
#include "func.h"
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

	if ( i<0 || i>entryCount() )
		return s;
	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(xn,i));

	if (!d)
		return s;

	s = ASN1_tag2str(d->type);
	return s;
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
	sl += getEntryTag(i);
	return sl;
}

int x509name::nid(int i) const
{
	X509_NAME_ENTRY *ne;
	int nid;

	ne = sk_X509_NAME_ENTRY_value(xn->entries, i);
	nid = OBJ_obj2nid(ne->object);
	return nid;
}

unsigned char *x509name::d2i(const unsigned char *p, int size)
{
	X509_NAME *xn_sik = xn;
	xn = D2I_CLASH(d2i_X509_NAME, NULL, &p, size);
	if (xn == NULL)
		xn = xn_sik;
	else
		X509_NAME_free(xn_sik);
	return (unsigned char *)p;
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
	return OBJ_txt2nid(nid_name.toAscii());
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

	for (int i=0;i<entry.length();i++)
		if(entry.at(i).unicode()>127) { need_uc=true; break; }

	if (need_uc) {
		unsigned char *data = (unsigned char *)OPENSSL_malloc(entry.length()*2);

		for (int i=0;i<entry.length();i++) {
			data[2*i] = entry.at(i).unicode() >> 8;
			data[2*i+1] = entry.at(i).unicode() & 0xff;
		}

		X509_NAME_add_entry_by_NID(xn, nid, V_ASN1_BMPSTRING,
					   data,entry.length()*2,-1,0);
		OPENSSL_free(data);
	}
	else {
		unsigned char *x = (unsigned char*)CCHAR(entry);
		int type = ASN1_PRINTABLE_type(x,-1);

		if (fix_data(nid, &type) == 0)
			return;

		X509_NAME_add_entry_by_NID(xn, nid, type, x,-1,-1,0);
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
