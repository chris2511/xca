/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __ASN1TIME_H
#define __ASN1TIME_H

#include <QtCore/QString>
#include <QtCore/QDateTime>
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
	void set_date(ASN1_TIME **a) const;
	void setUndefined();
	bool isUndefined() const;
	QString toPretty() const;
	QString toPlain() const;
	QString toSortable() const;
	int ymdg(struct tm *tm, int *g = NULL) const;
	int ymdg(int *y, int *m, int *d, int *h, int *M, int *s, int *g) const;
	ASN1_TIME *get() const;
	ASN1_TIME *get_utc() const;
	ASN1_GENERALIZEDTIME *get_generalized() const;
	a1time &now(int delta = 0);
	QByteArray i2d() const;
	void d2i(QByteArray &ba);
	QDateTime qDateTime() const;
	a1time &operator = (const a1time &a);
	bool operator > (const a1time &a);
	bool operator < (const a1time &a);
	bool operator == (const a1time &a);
	bool operator != (const a1time &a);
};

#endif
