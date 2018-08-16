/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2005 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __IPVALIDATOR_H
#define __IPVALIDATOR_H

#include <QStringList>
#include <QRegExp>
#include <QString>
#include <QValidator>

class ipValidator : public QValidator
{
    public:
	QValidator::State validate(QString &input, int&) const
	{
		QValidator::State state = Invalid;
		if (QRegExp("[0-9\\.]*").exactMatch(input)) {
			// IPv4
			QStringList octets = input.split(".");
			bool ok = octets.size() == 4;
			for (int i=0; ok && i<4; i++) {
				if (octets[i].toUInt(&ok) > 255)
					ok = false;
			}
			state = ok ? Acceptable : Intermediate;
		} else if (QRegExp("[0-9a-fA-F:]*").exactMatch(input)) {
			// IPv6
			QStringList words = input.split(":");
			bool ok = true;
			int empty = 0;

			for (int i=0; empty < 2 && ok && i<words.size(); i++) {
				empty += words[i].isEmpty() ? 1 : 0;
				if (words[i].toUInt(&ok, 16) > 0xffff)
					ok = false;
			}
			state = ok ? Acceptable : Intermediate;
		}
		qDebug() << "IP Valid:" << input << state;
		return state;
	}
	void fixup(QString &input) const
	{
		QString r = input.toLower();
	}
};
#endif
