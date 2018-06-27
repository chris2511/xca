/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012, 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __ASN1TIME_H
#define __ASN1TIME_H

#include <QString>
#include <QDateTime>
#include <openssl/asn1.h>

#define SECS_PER_MINUTE (60)
#define SECS_PER_HOUR (SECS_PER_MINUTE *60)
#define SECS_PER_DAY (SECS_PER_HOUR*24)

#define MSECS_PER_MINUTE (SECS_PER_MINUTE*1000)
#define MSECS_PER_HOUR (SECS_PER_HOUR*1000)

class a1time : public QDateTime
{
   private:
	ASN1_TIME *atime;
	int from_asn1(const ASN1_TIME *a);
	int set_asn1(const QString &str, int type);

   public:
	a1time();
	a1time(const QDateTime &a);
	a1time(const ASN1_TIME *a);
	a1time(const a1time &a);
	a1time(const QString &plain);
	a1time &operator = (const a1time &a);
	~a1time();
	a1time &set(const ASN1_TIME *a);
	int fromPlain(const QString &plain);
	a1time &setUndefined();
	bool isUndefined() const;
	QString toString(QString fmt, Qt::TimeSpec spec = Qt::UTC) const;
	QString toPretty() const;
	QString toPrettyGMT() const;
	QString toPlain(const QString &fmt = QString()) const;
	QString toPlainUTC() const;
	QString toSortable() const;
	QString toFancy() const;
	QString isoLocalDate() const;
	ASN1_TIME *get();
	ASN1_TIME *get_utc();
	static QDateTime now(int delta = 0);
	QByteArray i2d();
	void d2i(QByteArray &ba);
	qint64 age() const;
};

#endif
