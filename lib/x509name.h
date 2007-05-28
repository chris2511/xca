/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef X509NAME_H
#define X509NAME_H

#include <qstring.h>
#include <qstringlist.h>
#include <openssl/x509.h>

class x509name
{
	private:
		X509_NAME *xn;
	public:
		x509name();
		x509name(const X509_NAME *n);
		x509name(const x509name &n);
		~x509name();
		x509name &set(const X509_NAME *n);
		QString oneLine(unsigned long flags = XN_FLAG_ONELINE) const;
		int nid(int i) const;
		const unsigned char *d2i(const unsigned char *p, int size);
		unsigned char *i2d(unsigned char *p);
		QStringList entryList(int i) const;
		QString getEntryByNid(int nid ) const;
		QString getEntry(int i) const;
		QString getEntryTag(int i) const;
		int entryCount() const;
		x509name &operator = (const x509name &x);
		bool operator == (const x509name &x) const;
		static int getNidByName(const QString &nid_name);
		void addEntryByNid(int nid, const QString entry);
		void delEntry(int i);
		X509_NAME *get() const;
		int derSize() const;
};

#endif
