/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef ASN1TIME_H
#define ASN1TIME_H

#include <qstring.h>
#include <openssl/asn1.h>

#define SECONDS_PER_DAY (60*60*24)

class a1time
{
   private:
	ASN1_TIME *time;
	ASN1_UTCTIME *toUTCtime() const;
   public:
	a1time();
	a1time(const ASN1_TIME *a);
	a1time(const a1time &a);
	~a1time();
	a1time &set(const ASN1_TIME *a);
	a1time &set(time_t t);
	a1time &set(const QString &s);
	a1time &set(int y, int mon, int d, int h, int m, int s);
	void setUndefined();
	bool isUndefined() const;
	QString toPretty() const;
	QString toPlain() const;
	QString toSortable() const;
	int ymdg(struct tm *tm, int *g = NULL) const;
	int ymdg(int *y, int *m, int *d, int *h, int *M, int *s, int *g) const;
	ASN1_TIME *get() const;
	ASN1_TIME *get_utc() const;
	a1time &now(int delta = 0);
	unsigned char *i2d(unsigned char *p);
	unsigned char *d2i(const unsigned char *p, int size);
	int derSize() const;
	a1time &operator = (const a1time &a);
	bool operator > (const a1time &a);
	bool operator < (const a1time &a);
	bool operator == (const a1time &a);
	bool operator != (const a1time &a);
};

#endif
