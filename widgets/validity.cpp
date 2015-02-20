/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2003 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "validity.h"

#include <QDateTime>
#include "lib/asn1time.h"
#include "lib/func.h"


Validity::Validity( QWidget* parent )
    : QDateTimeEdit( parent )
{
	endDate = false;
	setTimeSpec(Qt::UTC);
	setNow();
	hideTime(false);
	connect(this, SIGNAL(timeChanged(const QTime &)),
		this, SLOT(setMyTime(const QTime &)));
	updateFormatString();
}

Validity::~Validity()
{
}

a1time Validity::getDate() const
{
	a1time date(dateTime());
	QTime time;

	if (midnight) {
		time = endDate ? QTime(23,59,59) : QTime(0,0,0);
		date.setTimeSpec(Qt::UTC);
	} else {
		time = date.time();
		time.setHMS(time.hour(), time.minute(), 0);
	}
	date.setTime(time);
	return date;
}

void Validity::localTime(int state)
{
	if (midnight)
		return;
	switch (state) {
	case Qt::Checked:
		setTimeSpec(Qt::LocalTime);
		setDateTime(dateTime().toLocalTime());
		break;
	case Qt::Unchecked:
		setTimeSpec(Qt::UTC);
		setDateTime(dateTime().toUTC());
		break;
	}
	updateFormatString();
	setMyTime(time());
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
		if (!midnight && endDate)
			setDateTime(dateTime().addDays(-1));
		midnight = true;
	} else {
		if (midnight && endDate)
			setDateTime(dateTime().addDays(1));
		midnight = false;
		setTime(mytime);
	}
	updateFormatString();
}

void Validity::updateFormatString()
{
	QString formatDate = tr("yyyy-MM-dd hh:mm");
	QString format;

	if (midnight) {
		if (!endDate)
			format = QTime(0,0,0).toString(formatDate);
		else
			format = QTime(23,59,59).toString(formatDate);
	} else {
		format = formatDate;
	}
	if (timeSpec() == Qt::UTC || midnight) {
		format += " 'GMT'";
	} else {
		format+= " t";
	}
	setDisplayFormat(format);
}

void Validity::setDate(const a1time &a)
{
	setDateTime(a);
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
	setMyTime(start->mytime);
}

void Validity::setNow()
{
	setDateTime(a1time::now());
	setMyTime(time());
}

void Validity::setMyTime(const QTime &time)
{
	mytime = time;
}

