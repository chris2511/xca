/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <time.h>

#include "base.h"
#include "func.h"
#include "exception.h"
#include "widgets/XcaApplication.h"
#include "asn1time.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#include <QObject>

/* As defined in rfc-5280  4.1.2.5 */
#define UNDEFINED_DATE "99991231235959Z"

#define UTC_FORMAT     "yyMMddHHmmss'Z'"
#define GEN_FORMAT     "yy" UTC_FORMAT

bool a1time::isUndefined() const
{
	return toTime_t() == 0;
}

a1time &a1time::setUndefined()
{
	/* This way we handle "Jan 01, 1970 00:00:00"
	 * like RFC-5280 undefined date. I dare it */
	setTimeSpec(Qt::UTC);
	setTime_t(0);
	return *this;
}

int a1time::from_asn1(const ASN1_TIME *a)
{
	ASN1_GENERALIZEDTIME *gt;
	QString t;

	*this = QDateTime();
	if (!a)
		return -1;
	gt = ASN1_TIME_to_generalizedtime((ASN1_TIME*)a, NULL);
	if (!gt)
		return -1;
	t = QString::fromLatin1((char*)gt->data, gt->length);
	ASN1_GENERALIZEDTIME_free(gt);
	return fromPlain(t);
}

int a1time::fromPlain(const QString &plain)
{
	setTimeSpec(Qt::LocalTime);
	if (plain == UNDEFINED_DATE)
		setUndefined();
	else
		*this = fromString(plain, GEN_FORMAT);
	setTimeSpec(Qt::UTC);
	return isValid() ? 0 : -1;
}

int a1time::set_asn1(const QString &str, int type)
{
	if (!atime)
		atime = ASN1_TIME_new();
	if (!atime)
		return -1;
	atime->type = type;
	if (ASN1_STRING_set(atime, str.toLatin1(), str.length()))
		return -1;
	return 0;
}

a1time::a1time(const QDateTime &a)
	: QDateTime(a)
{
	atime = NULL;
}

a1time::a1time(const a1time &a)
	: QDateTime(a)
{
	atime = NULL;
}

a1time &a1time::operator = (const a1time &a)
{
	if (atime)
		ASN1_TIME_free(atime);
	atime = NULL;
	QDateTime::operator=(a);
	return *this;
}

a1time::a1time()
{
	atime = NULL;
	*this = now();
}

a1time::a1time(const ASN1_TIME *a)
{
	atime = NULL;
	from_asn1(a);
}

a1time::a1time(const QString &plain)
{
	atime = NULL;
	fromPlain(plain);
}

a1time::~a1time()
{
	if (atime)
		ASN1_TIME_free(atime);
}

ASN1_TIME *a1time::get_utc()
{
	int year = date().year();

	if (!isValid() || isUndefined() || year > 2049 || year < 1950)
		return get();

	set_asn1(toUTC().toString(UTC_FORMAT), V_ASN1_UTCTIME);
	return atime;
}

ASN1_TIME *a1time::get()
{
	if (isUndefined())
		set_asn1(UNDEFINED_DATE, V_ASN1_GENERALIZEDTIME);
	else if (!isValid())
		throw errorEx("Invalid Time");
	else
		set_asn1(toUTC().toString(GEN_FORMAT),
			V_ASN1_GENERALIZEDTIME);
	return atime;
}

a1time &a1time::set(const ASN1_TIME *a)
{
	from_asn1(a);
	return *this;
}

QString a1time::toString(QString fmt, Qt::TimeSpec spec) const
{
	if (isUndefined())
		return QObject::tr("Undefined");
	if (!isValid())
		return QObject::tr("Broken / Invalid");
	return XcaApplication::language().toString(
		spec == Qt::UTC ? toUTC() : toLocalTime(), fmt);
}

QString a1time::toPretty() const
{
	QString fmt = XcaApplication::language().dateTimeFormat();
	return toString(fmt, Qt::LocalTime);
}

QString a1time::toPrettyGMT() const
{
	return toString("yyyy-MM-dd'T'HH:mm:ss' GMT'");
}

QString a1time::toSortable() const
{
	return toString("yyyy-MM-dd");
}

QString a1time::toPlain(const QString &fmt) const
{
	if (isUndefined())
		return QString(UNDEFINED_DATE);
	if (!isValid())
		return QString("Broken-InvalidZ");
	return toString(fmt.isEmpty() ? GEN_FORMAT : fmt);
}

qint64 a1time::age() const
{
	return secsTo(now());
}

QString a1time::toFancy() const
{
	QString fmt("Dunno");
	qint64 diff = age();
	int dtn = toLocalTime().daysTo(now().toLocalTime());
	bool future = false;
	if (diff < 0) {
		future = true;
		diff *= -1;
	}
	if (diff < 2 * SECS_PER_MINUTE) {
		fmt = future ? QObject::tr("in %1 seconds") :
				QObject::tr("%1 seconds ago");
	} else if (diff < 2 *SECS_PER_HOUR) {
		diff /= SECS_PER_MINUTE;
		fmt = future ? QObject::tr("in %1 minutes") :
				QObject::tr("%1 minutes ago");
	} else if (dtn == 1) {
		return QObject::tr("Yesterday");
	} else if (dtn == -1) {
		return QObject::tr("Tomorrow");
	} else if (diff < SECS_PER_DAY) {
		diff /= SECS_PER_HOUR;
		fmt = future ? QObject::tr("in %1 hours") :
				QObject::tr("%1 hours ago");
	} else {
		return XcaApplication::language().toString(date(),
			QLocale::ShortFormat);
	}
	return fmt.arg(diff);
}

QString a1time::toPlainUTC() const
{
	return toPlain(UTC_FORMAT);
}

QDateTime a1time::now(int delta)
{
	return QDateTime::currentDateTime().toUTC().addSecs(delta);
}

void a1time::d2i(QByteArray &ba)
{
	ASN1_TIME *n = (ASN1_TIME*)d2i_bytearray( D2I_VOID(d2i_ASN1_TIME), ba);
	openssl_error();
	if (n) {
		from_asn1(n);
		ASN1_TIME_free(n);
	}
}

QByteArray a1time::i2d()
{
	get();
	return i2d_bytearray(I2D_VOID(i2d_ASN1_TIME), atime);
}
