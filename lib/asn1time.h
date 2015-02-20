/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __ASN1TIME_H
#define __ASN1TIME_H

#include <QString>
#include <QDateTime>
#include <openssl/asn1.h>

#define SECONDS_PER_DAY (60*60*24)

class a1time : public QDateTime
{
   private:
	ASN1_TIME *atime;
	int from_asn1(const ASN1_TIME *a);
	int set_asn1(QString str, int type);

   public:
	a1time();
	a1time(const QDateTime &a);
	a1time(const ASN1_TIME *a);
	a1time(const a1time &a);
	a1time &operator = (const a1time &a);
	~a1time();
	a1time &set(const ASN1_TIME *a);
	void setUndefined();
	bool isUndefined() const;
	QString toPretty() const;
	QString toPrettyGMT() const;
	QString toPlain() const;
	QString toSortable() const;
	ASN1_TIME *get();
	ASN1_TIME *get_utc();
	static QDateTime now(int delta = 0);
	QByteArray i2d();
	void d2i(QByteArray &ba);
};

#endif
