/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __ASN1INTEGER_H
#define __ASN1INTEGER_H

#include <QString>
#include <openssl/asn1.h>

class a1int
{
   private:
	ASN1_INTEGER *in;
	ASN1_INTEGER *dup(const ASN1_INTEGER *a) const;
   public:
	a1int();
	a1int(const ASN1_INTEGER *i);
	a1int(const a1int &a);
	a1int(long l);
	~a1int();
	a1int &set(const ASN1_INTEGER *i);
	a1int &set(long l);
	QString toHex() const;
	QString toDec() const;
        a1int &setHex(const QString &s);
        a1int &setDec(const QString &s);
        a1int &setRaw(const unsigned char *data, unsigned len);
	long getLong() const;
	ASN1_INTEGER *get() const;
	QByteArray i2d();
	int derSize() const;

	a1int &operator ++ (void);
	a1int operator ++ (int);
	a1int &operator = (const a1int &a);
	a1int &operator = (long i);
	bool operator > (const a1int &a) const;
	bool operator < (const a1int &a) const;
	bool operator == (const a1int &a) const;
	bool operator != (const a1int &a) const;
};

#endif
