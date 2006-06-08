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
 *	written by Eric Young (eay@cryptsoft.com)"
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
	pki_counter--;
}


QString pki_base::getIntName() const
{
	return desc;
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
	openssl_error(txt);
}


void pki_base::openssl_error(const QString myerr)  const
{
	QString errtxt = "";
	QString error = "";
	if (myerr != "") {
		error += myerr + "\n";
	}
	while (int i = ERR_get_error() ) {
		errtxt = ERR_error_string(i ,NULL);
		printf("OpenSSL error: %s\n", ERR_error_string(i ,NULL) );
		error += errtxt + "\n";
	}
	if (!error.isEmpty()) {
		throw errorEx(error, class_name);
	}
}


bool pki_base::ign_openssl_error() const
{
	// ignore openssl errors
	QString errtxt;
	while (int i = ERR_get_error() ) {
	   errtxt = ERR_error_string(i ,NULL);
	   fprintf(stderr,"IGNORED: %s\n", CCHAR(errtxt));
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
	printf("r=%d, l=%d, s='%s', mid='%s'\n",r,l,(const char*)a,
			CCHAR(s.mid(l+1,r-l-1)));
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

int pki_base::alphabeticRow(QString name)
{
	int i;
	for (i=0; i< childItems.size(); i++) {
		//printf("CMP: '%s:%s'\n", CCHAR(childItems.at(i)->getIntName()),
		//		CCHAR(name));
		if (childItems.at(i)->getIntName() > name) {
			break;
		}
	}
	return i;
}

int pki_base::row(void) const
{
	if (parent)
		return parent->childItems.indexOf(const_cast<pki_base*>(this));
	return 0;
}

pki_base *pki_base::iterate(pki_base *pki)
{
	//printf("Iterate start, %p=%s, %p=%s childs:%d\n", this, CCHAR(this->getIntName()), pki, pki? CCHAR(pki->getIntName()):"--", this->childCount());
	if (pki == NULL)
		pki = (childItems.isEmpty()) ? NULL : childItems.first();
	else
		pki = childItems.value(pki->row()+1);
	//printf("Iterate middle, %p, %p\n", this, pki);
	if (pki) {
		//printf("Subchild %p\n", pki);
		return pki;
	}
	//printf("Parent = %p\n", parent);
	if (!parent)
		return NULL;
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

