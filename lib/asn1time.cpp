/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "base.h"
#include "func.h"
#include <time.h>
#include "asn1time.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <QtCore/QObject>

/* As defined in rfc-5280  4.1.2.5 */
#define UNDEFINED_DATE "99991231235959Z"
#define UTC_FORMAT     "yyMMddHHmmss'Z'"
#define GEN_FORMAT     "yy" UTC_FORMAT

int a1time::from_asn1(const ASN1_TIME *a)
{
	ASN1_GENERALIZEDTIME *gt;
	QString t;
	QDateTime dt;

	if (!a)
		return -1;
	gt = ASN1_TIME_to_generalizedtime((ASN1_TIME*)a, NULL);
	if (!gt)
		return -1;
	t = QString::fromAscii((char*)gt->data, gt->length);
	ASN1_GENERALIZEDTIME_free(gt);
	if (t == UNDEFINED_DATE) {
		*this = QDateTime();
		return 0;
	}
	dt = QDateTime::fromString(t, GEN_FORMAT);
	*this = dt;
	setTimeSpec(Qt::UTC);
	return 0;
}

int a1time::set_asn1(QString str, int type)
{
	if (!atime)
		atime = ASN1_TIME_new();
	if (!atime)
		return -1;
	atime->type = type;
	if (ASN1_STRING_set(atime, str.toAscii(), str.length()))
		return -1;
	return 0;
}

a1time::a1time(const QDateTime &a)
	: QDateTime(a)
{
	atime = NULL;
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

a1time::~a1time()
{
	if (atime)
		ASN1_TIME_free(atime);
}

ASN1_TIME *a1time::get_utc()
{
	int year = date().year();

	if (!isValid() || year > 2049 || year < 1950)
		return get();

	set_asn1(toUTC().toString(UTC_FORMAT), V_ASN1_UTCTIME);
	return atime;
}

ASN1_TIME *a1time::get()
{
	if (!isValid())
		set_asn1(UNDEFINED_DATE, V_ASN1_GENERALIZEDTIME);
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

QString a1time::toPretty() const
{
	if (!isValid())
		return QObject::tr("Undefined");

	return toLocalTime().toString(Qt::SystemLocaleLongDate);
}

QString a1time::toPrettyGMT() const
{
	if (!isValid())
		return QObject::tr("Undefined");

	return toUTC().toString(Qt::ISODate) + " GMT";
}

QString a1time::toPlain() const
{
	if (!isValid())
		return QString(UNDEFINED_DATE);
	return toUTC().toString(GEN_FORMAT);
}

QString a1time::toSortable() const
{
	if (!isValid())
		return QObject::tr("Undefined");
	return toUTC().toString("yyyy-MM-dd");
}

void a1time::setUndefined()
{
	*this = QDateTime();
}

QDateTime a1time::now(int delta)
{
	QDateTime dt = QDateTime::currentDateTime().toUTC().addSecs(delta);
	return dt;
}

void a1time::d2i(QByteArray &ba)
{
	ASN1_TIME *n = (ASN1_TIME*)d2i_bytearray( D2I_VOID(d2i_ASN1_TIME), ba);
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

