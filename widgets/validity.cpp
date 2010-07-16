/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "validity.h"

#include <QtCore/QDateTime>
#include "lib/asn1time.h"
#include "lib/func.h"

Validity::Validity( QWidget* parent )
    : QDateTimeEdit( parent )
{
	endDate = false;
	formatDate = tr("yyyy-MM-dd hh:mm");
#if QT_VERSION >= 0x040400
	setTimeSpec(Qt::UTC);
#endif
	setNow();
	hideTime(false);
	connect(this, SIGNAL(timeChanged(const QTime &)),
		this, SLOT(setMyTime(const QTime &)));
}

Validity::~Validity()
{
}

a1time Validity::getDate() const
{
	a1time date;
	QString postfix, format;

	if (midnight) {
		format = "yyyyMMdd";
		if (endDate) {
			postfix = "235959Z";
		} else {
			postfix = "000000Z";
		}
	} else {
		postfix = "00Z";
		format = "yyyyMMddhhmm";
	}
	date.set(dateTime().toString(format) + postfix);
	return date;
}

void Validity::hideTimeCheck(int state)
{
	switch (state) {
	case Qt::Checked:
		hideTime(true);
		break;
	case Qt::Unchecked:
		hideTime(false);
		break;
	}
}

void Validity::hideTime(bool hide)
{
	if (hide) {
		QString format;
		if (!endDate)
			format = QTime(0,0,0).toString(formatDate);
		else
			format = QTime(23,59,59).toString(formatDate);
		if (!midnight && endDate)
			setDateTime(dateTime().addDays(-1));
		midnight = true;
		setDisplayFormat(format);
	} else {
		setDisplayFormat(formatDate);
		if (midnight && endDate)
			setDateTime(dateTime().addDays(1));
		midnight = false;
		setTime(mytime);
	}
}

void Validity::setDate(const a1time &a)
{
	setDateTime(a.qDateTime());
}

void Validity::setDiff(const Validity *start, int number, int range)
{
	QDateTime dt = start->dateTime();

	switch (range) {
		case 0: dt = dt.addDays(number); break;
		case 1: dt = dt.addMonths(number); break;
		case 2: dt = dt.addYears(number); break;
	}

	// one day less if we go from 0:00:00 to 23:59:59
	if (midnight)
		dt = dt.addDays(-1);

	setDateTime(dt);
	mytime = start->mytime;
}

void Validity::setNow()
{
	QDateTime dt = QDateTime::currentDateTime().toUTC();

	setDateTime(dt);
	mytime = dt.time();
}

void Validity::setMyTime(const QTime &time)
{
	mytime = time;
}

