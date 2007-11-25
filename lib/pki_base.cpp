/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "pki_base.h"
#include "exception.h"
#include <QtCore/QString>

int pki_base::pki_counter = 0;

pki_base::pki_base(const QString name, pki_base *p)
{
	desc = name;
	class_name = "pki_base";
	parent = p;
	pki_counter++;
	childItems.clear();
	dataVersion=0;
	pkiType=none;
	cols=1;
}

int pki_base::getVersion()
{
	return dataVersion;
}

enum pki_type pki_base::getType()
{
	return pkiType;
}

pki_base::~pki_base(void)
{
	while((childCount()))
			delete takeFirst();
	pki_counter--;
}


QString pki_base::getIntName() const
{
	return desc;
}

QString pki_base::getUnderlinedName() const
{
	QString a = getIntName();
	int i, l = a.length();

	for (i=0; i<l; i++) {
		if (a[i] == ' ' || a[i] == '&' || a[i] == ';' || a[i] == '`')
			a[i] = '_';
	}

	return a;
}

int pki_base::get_pki_counter()
{
	return pki_counter;
}

QString pki_base::getClassName()
{
	QString x = class_name;
	return x;
}

void pki_base::setIntName(const QString &d)
{
	desc = d;
}

void pki_base::fopen_error(const QString fname)
{
	QString txt = "Error opening file: '" + fname + "'";
	throw errorEx(txt, class_name);
}

void pki_base::my_error(const QString error)  const
{
	if (!error.isEmpty()) {
		fprintf(stderr, "%s\n", CCHAR(tr("Error :") + error));
		throw errorEx(error, class_name);
	}
}

void pki_base::check_oom(const void *ptr) const
{
	if (!ptr)
		my_error(tr("Out of memory"));
}

void pki_base::openssl_error(const QString txt)  const
{
	QString errtxt = "";
	QString error = "";

	while (int i = ERR_get_error() ) {
		errtxt = ERR_error_string(i ,NULL);
		fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(i ,NULL) );
		error += errtxt + "\n";
	}
	if (!error.isEmpty()) {
		if (!txt.isEmpty())
			error = txt + "\n" + error;
		throw errorEx(error, class_name);
	}
}


bool pki_base::ign_openssl_error()
{
	// ignore openssl errors
	QString errtxt;
	while (int i = ERR_get_error() ) {
	   errtxt = ERR_error_string(i ,NULL);
	   //fprintf(stderr,"IGNORED: %s\n", CCHAR(errtxt));
	}
	return !errtxt.isEmpty();
}

QString pki_base::rmslashdot(const QString &s)
{
	QByteArray a = s.toAscii();
	int r = a.lastIndexOf('.');
#ifdef WIN32
	int l = a.lastIndexOf('\\');
#else
	int l = a.lastIndexOf('/');
#endif
	//printf("r=%d, l=%d, s='%s', mid='%s'\n",r,l,(const char*)a,
	//		CCHAR(s.mid(l+1,r-l-1)));
	return s.mid(l+1,r-l-1);
}

pki_base *pki_base::getParent()
{
	return parent;
}

void pki_base::setParent(pki_base *p)
{
	parent = p;
}

pki_base *pki_base::child(int row)
{
	return childItems.value(row);
}

void pki_base::append(pki_base *item)
{
	childItems.append(item);
	item->setParent(this);
}

void pki_base::insert(int row, pki_base *item)
{
	childItems.insert(row, item);
	item->setParent(this);
}

int pki_base::childCount()
{
	return childItems.count();
}

int pki_base::row(void) const
{
	if (parent)
		return parent->childItems.indexOf(const_cast<pki_base*>(this));
	return 0;
}

pki_base *pki_base::iterate(pki_base *pki)
{
	if (pki == NULL)
		pki = (childItems.isEmpty()) ? NULL : childItems.first();
	else
		pki = childItems.value(pki->row()+1);

	if (pki) {
		return pki;
	}
	if (!parent) {
		return NULL;
	}
	return parent->iterate(this);
}

void pki_base::takeChild(pki_base *pki)
{
	childItems.takeAt(pki->row());
}

pki_base *pki_base::takeFirst()
{
	return childItems.takeFirst();
}

int pki_base::columns(void)
{
	return cols;
}

QVariant pki_base::column_data(int col)
{
	return QVariant("invalid");
}
QVariant pki_base::getIcon()
{
	return QVariant();
}
void pki_base::oldFromData(unsigned char *p, int size)
{
}

uint32_t pki_base::intFromData(const unsigned char **p)
{
	/* For import "oldFromData" use the endian dependent version */
	int s = sizeof(uint32_t);
	uint32_t ret;
	memcpy(&ret, *p, s);
	*p += s;
	return ret;
}

