/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "validity.h"

#include <qdatetime.h>
#include "lib/asn1time.h"

Validity::Validity( QWidget* parent )
    : QDateTimeEdit( parent )
{
}

Validity::~Validity()
{
}

a1time Validity::getDate() const
{
	a1time date;
	date.set(dateTime().toString("yyyyMMddhhmmss") + "Z");
	return date;
}

void Validity::setDate(const a1time &a, int midnight)
{
	QDate date;
	QTime time;


	int y, m, d, h, min, s, g;
	QString S;

	a.ymdg(&y, &m, &d, &h, &min, &s, &g);

	if (midnight == 1) {
		h=0; min=0; s=0;
	}
	if (midnight == -1) {
		h=23; min=59; s=59;
	}

	date.setYMD(y,m,d);
	time.setHMS(h,min,s);

	QDateTime dt;
	dt.setDate(date);
	dt.setTime(time);
	setDateTime(dt);
}

void Validity::setNow()
{
	a1time a;
	setDate(a.now());
}

